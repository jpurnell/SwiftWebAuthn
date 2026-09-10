import Foundation
import Network

/// One parsed HTTP request. Only what routing needs.
public struct Request: Sendable, Equatable {
    /// The HTTP method, exactly as sent.
    public let method: String
    /// The request path, query string included.
    public let path: String
    /// The body, truncated to the declared `Content-Length`.
    public let body: Data

    /// Creates a request.
    /// - Parameters:
    ///   - method: The HTTP method.
    ///   - path: The request path.
    ///   - body: The body bytes.
    public init(method: String, path: String, body: Data) {
        self.method = method
        self.path = path
        self.body = body
    }
}

/// What to send back.
public struct Response: Sendable {
    /// Value for the `Content-Type` header.
    public let contentType: String
    /// The response body.
    public let body: Data

    /// Creates a response.
    /// - Parameters:
    ///   - contentType: Value for the `Content-Type` header.
    ///   - body: The body bytes.
    public init(contentType: String, body: Data) {
        self.contentType = contentType
        self.body = body
    }

    /// A JSON response.
    /// - Parameter value: The value to encode.
    /// - Returns: The response.
    /// - Throws: If encoding fails.
    public static func json(_ value: some Encodable) throws -> Response {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        return Response(contentType: "application/json", body: try encoder.encode(value))
    }

    /// An HTML response.
    /// - Parameter text: The page.
    /// - Returns: The response.
    public static func html(_ text: String) -> Response {
        Response(contentType: "text/html; charset=utf-8", body: Data(text.utf8))
    }
}

/// A single-purpose HTTP/1.1 server, on loopback only.
///
/// Deliberately minimal: it exists so a browser can reach this tool, and it is never exposed
/// beyond `127.0.0.1`. It understands one request per connection, closes afterwards, and refuses
/// a body larger than ``maximumBodySize`` — a capture tool has no reason to accept megabytes, and
/// an unbounded read here would be the one place this tool could be made to misbehave.
public final class HTTPServer: Sendable {

    /// The largest request body accepted. An attestation object is a couple of hundred bytes.
    public static let maximumBodySize = 64 * 1024

    private let port: NWEndpoint.Port
    private let route: @Sendable (Request) async -> Response

    /// Creates a server bound to loopback.
    /// - Parameters:
    ///   - port: The port to listen on.
    ///   - route: Answers one request.
    /// - Throws: ``CaptureError/badPort(_:)`` for a port that is not usable.
    public init(port: UInt16, route: @escaping @Sendable (Request) async -> Response) throws {
        guard let resolved = NWEndpoint.Port(rawValue: port) else {
            throw CaptureError.badPort(port)
        }
        self.port = resolved
        self.route = route
    }

    /// Starts listening. Returns once the listener is ready; serving continues in the background.
    public func start() throws {
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
    static let crlf = Data([0x0D, 0x0A])

    /// Splits header bytes on CRLF, without ever making them a `String` first.
    ///
    /// HTTP is a byte protocol whose line terminator is defined as two specific octets. Decoding
    /// the headers to text and splitting on a newline is where this goes wrong in both
    /// directions: in Swift a CRLF is a *single* `Character`, so `split(separator:)` compares
    /// something other than what arrived, and a scalar search leaves a stray carriage return on
    /// the end of every line. Neither throws. Both surface later, somewhere else.
    static func headerLines(of data: Data) -> [Data] {
        var lines: [Data] = []
        var start = data.startIndex
        while let separator = data[start...].range(of: crlf) {
            lines.append(data[start..<separator.lowerBound])
            start = separator.upperBound
        }
        if start < data.endIndex { lines.append(data[start...]) }
        return lines
    }

    /// What a buffer of received bytes amounts to so far.
    public enum ParseOutcome: Sendable, Equatable {
        /// The headers are not complete yet; read more.
        case incomplete
        /// A complete request.
        case complete(Request)
        /// Refused, and why. The connection is closed without answering.
        case refused(Refusal)

        /// Why a buffer was refused.
        public enum Refusal: String, Sendable, Equatable {
            /// More bytes than ``HTTPServer/maximumBodySize`` before a request was complete.
            case tooLarge
            /// A request line that is not `METHOD PATH VERSION`.
            case malformedRequestLine
            /// A `Content-Length` beyond the cap.
            case bodyTooLarge
            /// Two `Content-Length` headers that disagree.
            ///
            /// Named separately because the fault is not size. Whichever value this parser chose,
            /// something in front of it might choose the other, and the difference between them
            /// is a second request nobody authorised — so it is refused rather than resolved.
            case conflictingContentLength
        }
    }

    /// Decides what a buffer of received bytes amounts to, without touching a socket.
    ///
    /// Extracted so it can be attacked by a test. The quality gate found three defects in this
    /// parsing by reading it — a CRLF split that Swift's `Character` semantics make invisible,
    /// two unbounded loops, and a body read with no cap — and nothing had ever run it. Static
    /// analysis catching a bug is a gift; it is not a substitute for the bug being caught.
    ///
    /// - Parameter buffer: Everything received on this connection so far.
    /// - Returns: Whether to read more, answer, or hang up.
    public static func parse(_ buffer: Data) -> ParseOutcome {
        guard buffer.count <= maximumBodySize else { return .refused(.tooLarge) }
        guard let headerEnd = buffer.range(of: crlf + crlf) else { return .incomplete }

        let lines = headerLines(of: buffer[..<headerEnd.lowerBound])
        guard let requestLine = lines.first else { return .refused(.malformedRequestLine) }
        let parts = String(decoding: requestLine, as: UTF8.self).split(separator: " ")
        guard parts.count >= 2 else { return .refused(.malformedRequestLine) }

        guard let declared = contentLength(in: lines) else {
            return .refused(.conflictingContentLength)
        }
        guard declared <= maximumBodySize else { return .refused(.bodyTooLarge) }

        let body = buffer[headerEnd.upperBound...]
        guard body.count >= declared else { return .incomplete }

        return .complete(Request(
            method: String(parts[0]), path: String(parts[1]), body: Data(body.prefix(declared))
        ))
    }

    /// Accumulates until ``parse(_:)`` says the request is complete, then answers.
    ///
    /// The loop is bounded by ``maximumBodySize`` rather than running until something returns:
    /// a client that opens a connection and dribbles bytes forever must run out of welcome.
    private static func read(_ connection: NWConnection) async -> Request? {
        var buffer = Data()

        while buffer.count <= maximumBodySize {
            switch parse(buffer) {
            case .complete(let request): return request
            case .refused: return nil
            case .incomplete:
                guard let chunk = await receive(connection), !chunk.isEmpty else { return nil }
                buffer.append(chunk)
            }
        }
        return nil
    }

    /// The declared body length, or zero when no header names one.
    ///
    /// Case-insensitive because field names are, and it reads the **first** matching header
    /// rather than the last: a request carrying two `Content-Length` values is a request smuggling
    /// attempt, and disagreeing with the next parser about which one counts is how that works.
    /// A second, differing value returns nil, which the caller refuses by name.
    ///
    /// - Parameter lines: The header lines, already split on CRLF.
    /// - Returns: The declared length, or nil when two headers disagree.
    static func contentLength(in lines: [Data]) -> Int? {
        let name = "content-length:"
        var found: Int?
        for line in lines {
            let text = String(decoding: line, as: UTF8.self)
            guard text.lowercased().hasPrefix(name) else { continue }
            let value = Int(text.dropFirst(name.count).trimmingCharacters(in: .whitespaces)) ?? 0
            if let found, found != value { return nil }
            found = value
        }
        return found ?? 0
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
public enum CaptureError: Error, CustomStringConvertible {
    case badPort(UInt16)
    case noRegistrationYet
    case malformedRequest

    /// A sentence an operator can act on.
    public var description: String {
        switch self {
        case .badPort(let port): "not a usable port: \(port)"
        case .noRegistrationYet: "register before authenticating — there is no credential to assert"
        case .malformedRequest: "the browser sent something this tool could not read"
        }
    }
}
