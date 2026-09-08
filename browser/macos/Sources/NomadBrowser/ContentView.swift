import Combine
import SwiftUI

struct ContentView: View {
    @StateObject private var store = NomadStore()
    @State private var query = ""
    @State private var selectedDocument: VerifiedDocument?
    private let cacheRefresh = Timer.publish(
        every: NomadStore.publicCacheRefreshInterval,
        tolerance: 1,
        on: .main,
        in: .common
    ).autoconnect()

    private var results: [SearchResult] {
        LocalSearchEngine.search(query, documents: store.documents)
    }

    var body: some View {
        ZStack {
            LinearGradient(
                colors: [Color(red: 0.045, green: 0.035, blue: 0.09), Color(red: 0.10, green: 0.045, blue: 0.16)],
                startPoint: .topLeading,
                endPoint: .bottomTrailing
            )
            .ignoresSafeArea()

            VStack(spacing: 0) {
                header
                Divider().overlay(Color.white.opacity(0.10))
                if let selectedDocument {
                    documentView(selectedDocument)
                } else {
                    searchView
                }
            }
        }
        .preferredColorScheme(.dark)
        .onReceive(cacheRefresh) { _ in
            // This public timer is intentionally independent of the query and
            // selected document. Reloading performs local filesystem reads only.
            store.reload()
        }
    }

    private var header: some View {
        HStack(spacing: 12) {
            ZStack {
                RoundedRectangle(cornerRadius: 10)
                    .fill(LinearGradient(colors: [.purple, .indigo], startPoint: .topLeading, endPoint: .bottomTrailing))
                Image(systemName: "point.3.connected.trianglepath.dotted")
                    .font(.system(size: 19, weight: .semibold))
            }
            .frame(width: 38, height: 38)

            VStack(alignment: .leading, spacing: 1) {
                Text("Nomad")
                    .font(.system(size: 18, weight: .semibold, design: .rounded))
                Text("Verifierad lokal informationsyta")
                    .font(.caption)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Label("Nätåtkomst blockerad", systemImage: "lock.shield.fill")
                .font(.caption.weight(.medium))
                .foregroundStyle(.green)
                .padding(.horizontal, 11)
                .padding(.vertical, 7)
                .background(.green.opacity(0.10), in: Capsule())
        }
        .padding(.horizontal, 22)
        .padding(.vertical, 14)
    }

    private var searchView: some View {
        VStack(spacing: 24) {
            Spacer(minLength: 58)
            VStack(spacing: 10) {
                Text("Sök i Nomad")
                    .font(.system(size: 34, weight: .bold, design: .rounded))
                Text("Sökningen lämnar aldrig den privata domänen.")
                    .foregroundStyle(.secondary)
            }

            HStack(spacing: 12) {
                Image(systemName: "magnifyingglass")
                    .foregroundStyle(.secondary)
                TextField("Skriv en fråga eller ett ämne", text: $query)
                    .textFieldStyle(.plain)
                    .font(.title3)
                    .onSubmit { selectedDocument = results.first?.document }
                if !query.isEmpty {
                    Button {
                        query = ""
                    } label: {
                        Image(systemName: "xmark.circle.fill")
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                }
            }
            .padding(.horizontal, 18)
            .frame(maxWidth: 680, minHeight: 54)
            .background(.white.opacity(0.08), in: RoundedRectangle(cornerRadius: 15))
            .overlay(RoundedRectangle(cornerRadius: 15).stroke(.white.opacity(0.13)))

            Group {
                if query.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    VStack(spacing: 8) {
                        Text("Ingen adressrad. Ingen DNS. Ingen vanlig webb.")
                            .font(.headline)
                        Text("Klienten läser endast kryptografiskt verifierade objekt som redan finns i den lokala Nomad-cachen. Objektintegritet och SiteID-status visas som separata påståenden.")
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                            .multilineTextAlignment(.center)
                    }
                    .padding(.top, 8)
                } else if results.isEmpty {
                    ContentUnavailableView("Inga lokala träffar", systemImage: "tray", description: Text("Nätverket kontaktas inte som följd av sökningen."))
                } else {
                    ScrollView {
                        LazyVStack(spacing: 10) {
                            ForEach(results) { result in
                                Button {
                                    selectedDocument = result.document
                                } label: {
                                    resultRow(result)
                                }
                                .buttonStyle(.plain)
                            }
                        }
                    }
                    .frame(maxWidth: 760)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)

            statusFooter
        }
        .padding(.horizontal, 28)
    }

    private func resultRow(_ result: SearchResult) -> some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: "doc.text.fill")
                .font(.title2)
                .foregroundStyle(.purple)
                .frame(width: 34)
            VStack(alignment: .leading, spacing: 5) {
                Text(result.document.document.title)
                    .font(.headline)
                Text(result.document.document.summary)
                    .font(.subheadline)
                    .foregroundStyle(.secondary)
                    .lineLimit(2)
                verificationLine(result.document)
            }
            Spacer()
            Image(systemName: "chevron.right")
                .foregroundStyle(.tertiary)
        }
        .padding(16)
        .background(.white.opacity(0.055), in: RoundedRectangle(cornerRadius: 13))
        .overlay(RoundedRectangle(cornerRadius: 13).stroke(.white.opacity(0.08)))
    }

    private func documentView(_ verified: VerifiedDocument) -> some View {
        VStack(spacing: 0) {
            HStack {
                Button {
                    selectedDocument = nil
                } label: {
                    Label("Till sökningen", systemImage: "chevron.left")
                }
                .buttonStyle(.plain)
                Spacer()
                verificationLine(verified)
            }
            .padding(20)

            ScrollView {
                VStack(alignment: .leading, spacing: 18) {
                    Text(verified.document.title)
                        .font(.system(size: 34, weight: .bold, design: .rounded))
                    Text(verified.document.summary)
                        .font(.title3)
                        .foregroundStyle(.secondary)
                    Divider().overlay(.white.opacity(0.10))
                    Text(verified.document.body)
                        .font(.system(size: 17))
                        .lineSpacing(7)
                        .textSelection(.enabled)
                    HStack {
                        Text(verified.document.publisherName)
                        Text("• självuppgivet namn")
                        Text("•")
                        Text(verified.document.publishedAt)
                    }
                    .font(.caption)
                    .foregroundStyle(.secondary)
                }
                .frame(maxWidth: 760, alignment: .leading)
                .padding(.horizontal, 36)
                .padding(.bottom, 48)
            }
        }
    }

    @ViewBuilder
    private func verificationLine(_ verified: VerifiedDocument) -> some View {
        switch verified.publisherIdentity {
        case .verified:
            HStack(spacing: 6) {
                Image(systemName: "checkmark.seal.fill")
                Text("Objekt verifierat · aktuell SiteID-head verifierad")
                if let siteID = verified.siteID {
                    Text("· \(String(siteID.prefix(12)))…")
                }
            }
            .font(.caption2)
            .foregroundStyle(.green)
        case .unanchored:
            HStack(spacing: 6) {
                Image(systemName: "link.badge.plus")
                Text("Objekt verifierat · SiteID-kedja giltig men ej rollback-förankrad")
                if let siteID = verified.siteID {
                    Text("· \(String(siteID.prefix(12)))…")
                }
            }
            .font(.caption2)
            .foregroundStyle(.orange)
        case .unknown:
            HStack(spacing: 6) {
                Image(systemName: "checkmark.shield.fill")
                Text("Objekt verifierat · ingen SiteID-bevisning")
                Text("· nyckel \(verified.publisherFingerprint)")
            }
            .font(.caption2)
            .foregroundStyle(.orange)
        case .invalid:
            HStack(spacing: 6) {
                Image(systemName: "exclamationmark.shield.fill")
                Text("Objekt verifierat · SiteID-bevisning ogiltig")
            }
            .font(.caption2)
            .foregroundStyle(.red)
        }
    }

    private var statusFooter: some View {
        HStack {
            Text("\(store.documents.count) integritetsverifierade objekt")
            if store.rejectedObjectCount > 0 {
                Text("· \(store.rejectedObjectCount) avvisade")
                    .foregroundStyle(.orange)
            }
            Spacer()
            Label("Cache uppdateras automatiskt", systemImage: "arrow.triangle.2.circlepath")
        }
        .font(.caption)
        .foregroundStyle(.secondary)
        .padding(.vertical, 16)
    }
}
