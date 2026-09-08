import SwiftUI

@main
struct NomadBrowserApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(\.openURL, OpenURLAction { _ in .discarded })
                .frame(minWidth: 920, minHeight: 620)
        }
        .windowStyle(.hiddenTitleBar)
        .commands {
            CommandGroup(replacing: .newItem) { }
            CommandGroup(replacing: .help) { }
        }
    }
}
