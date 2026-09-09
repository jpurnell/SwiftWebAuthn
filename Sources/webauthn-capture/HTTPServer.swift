import Foundation
import Network

/// One parsed HTTP request. Only what routing needs.
struct Request {
    let method: String
    let path: String
    let body: Data
}

/// What to send back.
struct Response {
    let contentType: String
    let body: Data

    static func json(_ value: some Encodable) throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return Response(contentType: "application/json", body: try encoder.encode(value))
    }

    static func html(_ text: String) -> Response {
        Response(contentType: "text/html; charset=utf-8", body: Data(text.utf8))
    }
}

/// A single-purpose HTTP/1.1 server, on loopback only.
///
/// Deliberately minimal: it exists so a browser can reach this tool, and it is never exposed
/// beyond `127.0.0.1`. It understands one request per connection, closes afterwards, and refuses
/// a body larger than ``maximumBodySize`` — a capture tool has no reason to accept megabytes, and
/// an unbounded read here would be the one place this tool could be made to misbehave.
final class HTTPServer: Sendable {

    /// The largest request body accepted. An attestation object is a couple of hundred bytes.
    static let maximumBodySize = 64 * 1024

    private let port: NWEndpoint.Port
    private let route: @Sendable (Request) async -> Response

    init(port: UInt16, route: @escaping @Sendable (Request) async -> Response) throws {
        guard let resolved = NWEndpoint.Port(rawValue: port) else {
            throw CaptureError.badPort(port)
        }
        self.port = resolved
        self.route = route
    }

    /// Starts listening. Returns once the listener is ready; serving continues in the background.
    func start() throws {
        let parameters = NWParameters.tcp
        // Loopback only. A tool that mints WebAuthn challenges should not be reachable from the
        // network, and binding narrowly is cheaper than remembering not to.
        parameters.requiredLocalEndpoint = .hostPort(host: "127.0.0.1", port: port)
        parameters.allowLocalEndpointReuse = true

        let listener = try NWListener(using: parameters)
        listener.newConnectionHandler = { [route] connection in
            connection.start(queue: .global())
            Task { await Self.serve(connection, route: route) }
        }
        listener.start(queue: .global())
    }

    /// Reads one request, answers it, and closes.
    private static func serve(
        _ connection: NWConnection, route: @Sendable (Request) async -> Response
    ) async {
        defer { connection.cancel() }
        guard let request = await read(connection) else { return }
        let response = await route(request)
        await send(response, on: connection)
    }

    /// The CRLF that separates header lines, as bytes.
    private static let crlf = Data([0x0D, 0x0A])

    /// Splits header bytes on CRLF, without ever making them a `String` first.
    ///
    /// HTTP is a byte protocol whose line terminator is defined as two specific octets. Decoding
    /// the headers to text and splitting on a newline is where this goes wrong in both
    /// directions: in Swift a CRLF is a *single* `Character`, so `split(separator:)` compares
    /// something other than what arrived, and a scalar search leaves a stray carriage return on
    /// the end of every line. Neither throws. Both surface later, somewhere else.
    private static func headerLines(of data: Data) -> [Data] {
        var lines: [Data] = []
        var start = data.startIndex
        while let separator = data[start...].range(of: crlf) {
            lines.append(data[start..<separator.lowerBound])
            start = separator.upperBound
        }
        if start < data.endIndex { lines.append(data[start...]) }
        return lines
    }

    /// Accumulates until the headers are complete, then reads exactly `Content-Length` bytes.
    ///
    /// The loop is bounded by ``maximumBodySize`` rather than running until something returns:
    /// a client that opens a connection and dribbles bytes forever must run out of welcome.
    private static func read(_ connection: NWConnection) async -> Request? {
        var buffer = Data()

        while buffer.count <= maximumBodySize {
            guard let chunk = await receive(connection), !chunk.isEmpty else { return nil }
            buffer.append(chunk)

            guard let headerEnd = buffer.range(of: crlf + crlf) else { continue }

            let lines = headerLines(of: buffer[..<headerEnd.lowerBound])
            guard let requestLine = lines.first else { return nil }
            let parts = String(decoding: requestLine, as: UTF8.self).split(separator: " ")
            guard parts.count >= 2 else { return nil }

            let declared = contentLength(in: lines)
            guard declared <= maximumBodySize else { return nil }

            var body = buffer[headerEnd.upperBound...]
            while body.count < declared {
                guard let more = await receive(connection), !more.isEmpty else { return nil }
                body.append(more)
            }

            return Request(
                method: String(parts[0]), path: String(parts[1]), body: Data(body.prefix(declared))
            )
        }
        return nil
    }

    /// The declared body length, or zero when no header names one.
    private static func contentLength(in lines: [Data]) -> Int {
        let name = "content-length:"
        for line in lines {
            let text = String(decoding: line, as: UTF8.self)
            guard text.lowercased().hasPrefix(name) else { continue }
            return Int(text.dropFirst(name.count).trimmingCharacters(in: .whitespaces)) ?? 0
        }
        return 0
    }

    /// One `receive`, bridged to async.
    private static func receive(_ connection: NWConnection) async -> Data? {
        await withCheckedContinuation { continuation in
            connection.receive(minimumIncompleteLength: 1, maximumLength: 16 * 1024) { data, _, _, _ in
                continuation.resume(returning: data)
            }
        }
    }

    private static func send(_ response: Response, on connection: NWConnection) async {
        let head = """
            HTTP/1.1 200 OK\r
            Content-Type: \(response.contentType)\r
            Content-Length: \(response.body.count)\r
            Connection: close\r
            \r

            """
        var payload = Data(head.utf8)
        payload.append(response.body)

        await withCheckedContinuation { continuation in
            connection.send(content: payload, completion: .contentProcessed { _ in
                continuation.resume()
            })
        }
    }
}

/// What can go wrong before a ceremony is even attempted.
enum CaptureError: Error, CustomStringConvertible {
    case badPort(UInt16)
    case noRegistrationYet
    case malformedRequest

    var description: String {
        switch self {
        case .badPort(let port): "not a usable port: \(port)"
        case .noRegistrationYet: "register before authenticating — there is no credential to assert"
        case .malformedRequest: "the browser sent something this tool could not read"
        }
    }
}
