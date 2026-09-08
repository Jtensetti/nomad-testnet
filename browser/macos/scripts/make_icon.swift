import AppKit
import Foundation

guard CommandLine.arguments.count == 2 else {
    fputs("usage: make_icon.swift OUTPUT.png\n", stderr)
    exit(2)
}

let size = NSSize(width: 1024, height: 1024)
let image = NSImage(size: size)
image.lockFocus()

let rect = NSRect(origin: .zero, size: size)
let background = NSBezierPath(roundedRect: rect.insetBy(dx: 22, dy: 22), xRadius: 224, yRadius: 224)
let gradient = NSGradient(colorsAndLocations:
    (NSColor(calibratedRed: 0.16, green: 0.04, blue: 0.28, alpha: 1), 0),
    (NSColor(calibratedRed: 0.35, green: 0.10, blue: 0.62, alpha: 1), 0.56),
    (NSColor(calibratedRed: 0.10, green: 0.22, blue: 0.48, alpha: 1), 1)
)
gradient?.draw(in: background, angle: -45)

NSColor.white.withAlphaComponent(0.13).setStroke()
background.lineWidth = 10
background.stroke()

let points = [
    NSPoint(x: 264, y: 276),
    NSPoint(x: 512, y: 744),
    NSPoint(x: 760, y: 276)
]
let connection = NSBezierPath()
connection.move(to: points[0])
connection.line(to: points[1])
connection.line(to: points[2])
connection.line(to: points[0])
connection.lineWidth = 44
connection.lineCapStyle = .round
connection.lineJoinStyle = .round
NSColor.white.withAlphaComponent(0.91).setStroke()
connection.stroke()

for (index, point) in points.enumerated() {
    let radius: CGFloat = index == 1 ? 74 : 62
    let circle = NSBezierPath(ovalIn: NSRect(x: point.x - radius, y: point.y - radius, width: radius * 2, height: radius * 2))
    NSColor.white.setFill()
    circle.fill()
    NSColor(calibratedRed: 0.29, green: 0.08, blue: 0.50, alpha: 1).setStroke()
    circle.lineWidth = 18
    circle.stroke()
}

image.unlockFocus()
guard
    let tiff = image.tiffRepresentation,
    let bitmap = NSBitmapImageRep(data: tiff),
    let png = bitmap.representation(using: .png, properties: [:])
else {
    fputs("could not render icon\n", stderr)
    exit(1)
}
try png.write(to: URL(fileURLWithPath: CommandLine.arguments[1]), options: .atomic)
