import Foundation
import Testing
@testable import CaptureHTTP

/// The parser the quality gate found three defects in, now actually executed.
///
/// Those defects — a CRLF split that Swift's `Character` semantics make invisible, two unbounded
/// loops, and a body read with no cap — were caught by static analysis reading the code. Nothing
/// had ever run it. Static analysis catching a bug is a gift; it is not a substitute for the bug
/// being catchable.
///
/// These are written from the attacker's side, because that is who sends the bytes.
@Suite("CaptureHTTP — parsing bytes somebody else chose")
struct RequestParsingTests {

    private static func bytes(_ text: String) -> Data { Data(text.utf8) }

    // MARK: - The positive control

    @Test("an ordinary GET")
    func anOrdinaryGet() {
        let outcome = HTTPServer.parse(Self.bytes("GET /calendar HTTP/1.1\r\nHost: x\r\n\r\n"))
        #expect(outcome == .complete(.init(method: "GET", path: "/calendar", body: Data())))
    }

    @Test("a POST whose body has arrived")
    func aCompletePost() {
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 5\r\n\r\nhello")
        )
        #expect(outcome == .complete(.init(method: "POST", path: "/r", body: Self.bytes("hello"))))
    }

    // MARK: - Incomplete, which must never be mistaken for malformed

    @Test("headers that have not finished arriving")
    func partialHeaders() {
        #expect(HTTPServer.parse(Data()) == .incomplete)
        #expect(HTTPServer.parse(Self.bytes("GET /r HTTP/1.1\r\nHos")) == .incomplete)
        #expect(HTTPServer.parse(Self.bytes("GET /r HTTP/1.1\r\n\r")) == .incomplete)
    }

    @Test("a body that has not finished arriving")
    func partialBody() {
        // The dangerous mistake here is answering early with a truncated body, which is how a
        // form field silently loses its tail.
        #expect(HTTPServer.parse(Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 5\r\n\r\nhel")) == .incomplete)
    }

    @Test("a body longer than declared is truncated to what was declared, not passed on whole")
    func overlongBodyIsTruncated() {
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 5\r\n\r\nhelloAND MORE")
        )
        // Extra bytes after `Content-Length` are the next request on a reused connection, or an
        // attempt to have two parsers disagree about where this one ended.
        #expect(outcome == .complete(.init(method: "POST", path: "/r", body: Self.bytes("hello"))))
    }

    // MARK: - Line endings, which is where the original defect lived

    @Test("a bare LF does not end the header block")
    func bareLineFeedIsNotATerminator() {
        // HTTP defines CRLF. A parser that accepted a bare LF would end the headers somewhere a
        // stricter parser in front of it did not — the request smuggling primitive.
        #expect(HTTPServer.parse(Self.bytes("GET /r HTTP/1.1\nHost: x\n\n")) == .incomplete)
    }

    @Test("a lone CR inside a header does not split it")
    func loneCarriageReturnDoesNotSplit() {
        let outcome = HTTPServer.parse(
            Self.bytes("GET /r HTTP/1.1\r\nX-Odd: a\rb\r\nContent-Length: 0\r\n\r\n")
        )
        #expect(outcome == .complete(.init(method: "GET", path: "/r", body: Data())))
    }

    @Test("header lines split on CRLF exactly, leaving no carriage return behind")
    func headerLinesAreSplitOnBytes() {
        let lines = HTTPServer.headerLines(of: Self.bytes("GET / HTTP/1.1\r\nA: 1\r\nB: 2"))
        #expect(lines.count == 3)
        // A stray \r on the end of every line is what a scalar-based split leaves, and it makes
        // every suffix check and every comparison one character wrong.
        #expect(lines.allSatisfy { !$0.contains(0x0D) })
        #expect(String(decoding: lines[2], as: UTF8.self) == "B: 2")
    }

    // MARK: - Content-Length, which is where smuggling lives

    @Test("two disagreeing Content-Length headers are refused, never resolved")
    func conflictingContentLengthsAreRefused() {
        // Whichever one this parser picked, something in front of it might pick the other, and
        // the difference is a second request nobody authorised.
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello!")
        )
        #expect(outcome == .refused(.conflictingContentLength))
    }

    @Test("two agreeing ones are fine")
    func duplicateAgreeingContentLengthsAreAccepted() {
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello")
        )
        #expect(outcome == .complete(.init(method: "POST", path: "/r", body: Self.bytes("hello"))))
    }

    @Test("the header name is matched case-insensitively, as HTTP defines it")
    func contentLengthIsCaseInsensitive() {
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\ncOnTeNt-LeNgTh: 2\r\n\r\nhi")
        )
        #expect(outcome == .complete(.init(method: "POST", path: "/r", body: Self.bytes("hi"))))
    }

    @Test("a declared length past the cap is refused without allocating it")
    func absurdContentLengthIsRefused() {
        let outcome = HTTPServer.parse(
            Self.bytes("POST /r HTTP/1.1\r\nContent-Length: 999999999\r\n\r\n")
        )
        #expect(outcome == .refused(.bodyTooLarge))
    }

    @Test("and a buffer past the cap is refused however it got there")
    func oversizeBufferIsRefused() {
        let padding = String(repeating: "x", count: HTTPServer.maximumBodySize + 1)
        #expect(HTTPServer.parse(Self.bytes(padding)) == .refused(.tooLarge))
    }

    // MARK: - Request line

    @Test("a request line missing its path")
    func malformedRequestLines() {
        #expect(HTTPServer.parse(Self.bytes("GET\r\n\r\n")) == .refused(.malformedRequestLine))
        #expect(HTTPServer.parse(Self.bytes("\r\n\r\n")) == .refused(.malformedRequestLine))
    }

    @Test("a request line that is not valid UTF-8 does not crash the parser")
    func invalidUTF8InTheRequestLine() {
        var raw = Data([0xFF, 0xFE, 0x20, 0x2F, 0x20])   // <invalid> / <space>
        raw.append(Self.bytes("HTTP/1.1\r\n\r\n"))
        // Whatever it decides, it must decide — `String(decoding:)` substitutes replacement
        // characters rather than failing, so the danger is a confident wrong answer, not a trap.
        let outcome = HTTPServer.parse(raw)
        #expect(outcome != .incomplete)
    }
}
