// Draws the app icon (1024×1024 PNG): "LabDC" — a warm-cream squircle with a short, thick key
// (open bow, two teeth) in near-black and three green bubbles rising to its upper right, like a
// lab experiment at work (owner's pick "D1", 1 Oct 2026). Drawn on a 120-unit grid (the sketch's
// viewBox) and scaled onto the 824 pt squircle.
// Usage: swift Scripts/make-icon.swift Sources/LabDCApp/Bundle/AppIcon.png
import AppKit

let path = CommandLine.arguments.dropFirst().first ?? "AppIcon.png"
let size: CGFloat = 1024

func color(_ hex: UInt32) -> NSColor {
    NSColor(calibratedRed: CGFloat(hex >> 16 & 0xFF) / 255, green: CGFloat(hex >> 8 & 0xFF) / 255,
            blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
}
let cream = color(0xF1EFE8)
let ink = color(0x2C2C2A)
let greens = [color(0x1D9E75), color(0x5DCAA5), color(0x9FE1CB)]

// Sketch grid → pixels: the squircle spans 6…114 units = 100…924 px; y flips (AppKit is y-up).
let k: CGFloat = 824 / 108
func p(_ x: CGFloat, _ y: CGFloat) -> NSPoint { NSPoint(x: 100 + (x - 6) * k, y: 924 - (y - 6) * k) }

guard let rep = NSBitmapImageRep(bitmapDataPlanes: nil, pixelsWide: Int(size), pixelsHigh: Int(size), bitsPerSample: 8,
                                 samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
                                 bytesPerRow: 0, bitsPerPixel: 0) else { fatalError("no bitmap") }
NSGraphicsContext.saveGraphicsState()
NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)

// The squircle: white at the top fading to cream.
let shape = NSBezierPath(roundedRect: NSRect(x: 100, y: 100, width: 824, height: 824), xRadius: 185, yRadius: 185)
NSGradient(starting: .white, ending: cream)!.draw(in: shape, angle: -90)
shape.addClip()

// The key: an open bow, a short shaft, two teeth.
ink.setStroke()
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

// Three bubbles rising, largest and deepest green first.
for (i, (x, y, r)) in [(CGFloat(72), CGFloat(44), CGFloat(9)), (88, 28, 6), (96, 48, 4)].enumerated() {
    greens[i].setFill()
    let c = p(x, y)
    NSBezierPath(ovalIn: NSRect(x: c.x - r * k, y: c.y - r * k, width: 2 * r * k, height: 2 * r * k)).fill()
}

NSGraphicsContext.restoreGraphicsState()
try! rep.representation(using: .png, properties: [:])!.write(to: URL(fileURLWithPath: path))
print("wrote \(path)")
