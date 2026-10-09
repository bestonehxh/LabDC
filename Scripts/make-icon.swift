// Draws the app icon (1024×1024 PNG): "LabDC" in the Lab family look shared with LabDock — a charcoal
// squircle with one glyph in the app's own tint (LabDock: an empty mint frame). LabDC is the key from
// its first icon (open round bow, short shaft, two teeth) in orange, centred, without the bubbles
// (owner, 9 Oct 2026; replaces the cream key-and-bubbles "D1" of 1 Oct 2026). Drawn on the old icon's
// 120-unit grid, scaled so it fills the same box as LabDock's frame (outer edge 220…804 px, so the same
// margin to the squircle) and centred.
// Usage: swift Scripts/make-icon.swift Sources/LabDCApp/Bundle/AppIcon.png
import AppKit

let path = CommandLine.arguments.dropFirst().first ?? "AppIcon.png"
let size: CGFloat = 1024

func color(_ hex: UInt32) -> NSColor {
    NSColor(calibratedRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}
let charcoal = color(0x1F2125), charcoalTop = color(0x2A2D33)
let orange = color(0xF2B866)

guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                                 samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                 bytesPerRow: 0, bitsPerPixel: 0) else { fatalError("no bitmap") }
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

// The squircle.
let shape = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
NSGradient(starting: charcoalTop, ending: charcoal)!.draw(in: shape, angle: -90)

// Sketch grid → pixels; y flips (AppKit is y-up). The key, strokes included, spans x 27…84 and
// y 55…102.5 units: its 57-unit width is stretched to the frame's 584 px and its centre put at 512, 512.
let k: CGFloat = 584 / 57
func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: 512 + (x - 55.5) * k, y: 512 - (y - 78.75) * k) }

// The key: an open bow, a short shaft, two teeth.
orange.setStroke()
let bow = NSBezierPath(ovalIn: NSRect(x: p(44, 72).x - 13 * k, y: p(44, 72).y - 13 * k, width: 26 * k, height: 26 * k))
bow.lineWidth = 8 * k
bow.stroke()
func stroke(_ a: NSPoint, _ b: NSPoint, width: CGFloat) {
    let line = NSBezierPath()
    line.move(to: a); line.line(to: b)
    line.lineWidth = width * k
    line.lineCapStyle = .round
    line.stroke()
}
stroke(p(55, 79), p(80, 94), width: 8)
stroke(p(69, 87), p(65, 94), width: 7)
stroke(p(78, 92), p(74, 99), width: 7)

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
print("wrote \(path)")
