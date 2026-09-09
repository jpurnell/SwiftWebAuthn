import Testing
@testable import SwiftWebAuthn

/// A placeholder suite.
///
/// The real tests come from the W3C specification's verification steps, one named test per
/// numbered step, so coverage can be checked against the document rather than against anyone's
/// judgement — plus ceremonies captured from the deployment's own devices. See
/// `project/plans/proposals/RelyingPartyImplementation.md` §6.
@Suite("SwiftWebAuthn")
struct SwiftWebAuthnTests {

    @Test("the package builds and exposes its namespace")
    func namespaceExists() {
        #expect(SwiftWebAuthn.self == SwiftWebAuthn.self)
    }
}
