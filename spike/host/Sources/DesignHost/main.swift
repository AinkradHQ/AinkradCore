// V0-01 spike host: CAMetalLayer view + display link at the display rate, native gestures, and a
// scripted measurement mode (`--measure <outdir>`). Throwaway.
import AppKit
import CDesign
import Metal
import QuartzCore

// ---------- args ----------
var argv = Array(CommandLine.arguments.dropFirst())
func opt(_ name: String) -> String? {
    if let i = argv.firstIndex(of: name), i + 1 < argv.count { return argv[i + 1] }
    return nil
}
let fontPath = opt("--font") ?? "/System/Library/Fonts/Supplemental/Arial.ttf"
let measureDir = opt("--measure")
var postedDrags = 0, gotDrags = 0
let benchDir = opt("--bench")
let noLod = argv.contains("--no-lod")
let barsMaxW = opt("--bars-max-w").flatMap { Float($0) }
let blurMinW = opt("--blur-min-w").flatMap { Float($0) }
let rmArg = opt("--reduce-motion")  // "on" | "off" for interactive mode; measure mode tests both

func now() -> Double { CACurrentMediaTime() }
func pct(_ v: [Double], _ p: Double) -> Double {
    if v.isEmpty { return .nan }
    let s = v.sorted()
    return s[min(s.count - 1, Int((Double(s.count - 1) * p).rounded(.up)))]
}
func residentMB() -> Double {
    var info = task_vm_info_data_t()
    var count = mach_msg_type_number_t(MemoryLayout<task_vm_info_data_t>.size / MemoryLayout<integer_t>.size)
    let r = withUnsafeMutablePointer(to: &info) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) { task_info(mach_task_self_, task_flavor_t(TASK_VM_INFO), $0, &count) }
    }
    return r == KERN_SUCCESS ? Double(info.phys_footprint) / 1_048_576 : -1
}

// ---------- frame log ----------
final class Frame { var phase = ""; var idx = 0; var tick = 0.0; var acquireMs = 0.0; var skiaMs = 0.0; var totalCpuMs = 0.0
    var gpuDoneMs = 0.0; var presented = 0.0; var zoom: Float = 0 }
struct DragEv { var stamp: Double; var applied: Double; var submitted = 0.0; var presented = 0.0 }

final class Store: @unchecked Sendable {
    let lock = NSLock()
    var frames: [Frame] = []
    var drags: [DragEv] = []
    func with<T>(_ f: () -> T) -> T { lock.lock(); defer { lock.unlock() }; return f() }
}

// ---------- view ----------
final class CanvasView: NSView {
    var eng: OpaquePointer!
    let device = MTLCreateSystemDefaultDevice()!
    lazy var queue = device.makeCommandQueue()!
    var metalLayer: CAMetalLayer { layer as! CAMetalLayer }
    let store = Store()
    var dirty = true
    var phase = "interactive"
    var frameIdx = 0
    var reduceMotion = false
    var link: CAMetalDisplayLink?
    var lastTarget = 0.0
    var script: Script?
    // gestures state
    var vel = CGPoint.zero, glideActive = false, glideFrames = 0, glideDist = 0.0
    var pendingStamps: [DragEv] = []
    var dragging = false
    var ticksInPhase = 0, framesInPhase = 0

    override var isFlipped: Bool { true }
    override var acceptsFirstResponder: Bool { true }
    override func makeBackingLayer() -> CALayer {
        let l = CAMetalLayer()
        l.device = device
        l.pixelFormat = .bgra8Unorm
        l.framebufferOnly = false  // Skia samples/reads the drawable
        l.maximumDrawableCount = 2
        l.displaySyncEnabled = true
        return l
    }
    override init(frame: NSRect) { super.init(frame: frame); wantsLayer = true; layerContentsRedrawPolicy = .never }
    required init?(coder: NSCoder) { fatalError() }

    var scale: CGFloat { window?.backingScaleFactor ?? 2 }
    func syncSize() {
        metalLayer.contentsScale = scale
        metalLayer.drawableSize = CGSize(width: bounds.width * scale, height: bounds.height * scale)
        ds_set_view(eng, Float(bounds.width), Float(bounds.height), Float(scale))
        dirty = true
    }
    override func layout() { super.layout(); syncSize() }

    func startLink() {
        let l = CAMetalDisplayLink(metalLayer: metalLayer)
        l.delegate = self
        l.preferredFrameLatency = 1
        l.preferredFrameRateRange = CAFrameRateRange(minimum: Float(ProcessInfo.processInfo.environment["DS_LINK_MIN"] ?? "80") ?? 80, maximum: 120, preferred: 120)
        l.add(to: .main, forMode: .common)
        link = l
    }

    // ----- native gestures: every entry point ends in these three handlers -----
    func handleMagnify(_ delta: CGFloat, at p: CGPoint) {
        ds_zoom_at(eng, Float(1 + delta), Float(p.x), Float(p.y)); dirty = true; glideActive = false
    }
    enum Ph { case began, changed, ended, none }
    func handleScroll(dx: CGFloat, dy: CGFloat, phase: Ph, dt: Double = 1.0 / 120) {
        switch phase {
        case .began: glideActive = false; vel = .zero
        case .changed, .none:
            ds_pan(eng, Float(dx), Float(dy)); dirty = true
            vel = CGPoint(x: vel.x * 0.5 + (dx / dt) * 0.5, y: vel.y * 0.5 + (dy / dt) * 0.5)
        case .ended:
            // Reduce Motion: no momentum glide, the motion just stops.
            if !reduceMotion, hypot(vel.x, vel.y) > 50 { glideActive = true; glideFrames = 0; glideDist = 0 } else { glideActive = false }
        }
    }
    override func scrollWheel(with e: NSEvent) {
        if !e.momentumPhase.isEmpty { return }  // the app owns momentum (so Reduce Motion can turn it off)
        let ph: Ph = e.phase.contains(.began) || e.phase.contains(.mayBegin) ? .began : (e.phase.contains(.ended) || e.phase.contains(.cancelled) ? .ended : (e.phase.isEmpty ? .none : .changed))
        if e.modifierFlags.contains(.command) { handleMagnify(e.scrollingDeltaY * 0.01, at: convert(e.locationInWindow, from: nil)); return }
        handleScroll(dx: e.scrollingDeltaX, dy: e.scrollingDeltaY, phase: ph)
    }
    override func magnify(with e: NSEvent) { handleMagnify(e.magnification, at: convert(e.locationInWindow, from: nil)) }
    override func mouseDown(with e: NSEvent) {
        let p = convert(e.locationInWindow, from: nil)
        dragging = ds_drag_begin(eng, Float(p.x), Float(p.y)) != 0
        FileHandle.standardError.write("mouseDown at \(p) dragging=\(dragging)\n".data(using: .utf8)!)
    }
    override func mouseDragged(with e: NSEvent) {
        gotDrags += 1
        let p = convert(e.locationInWindow, from: nil)
        if dragging {
            ds_drag_move(eng, Float(p.x), Float(p.y))
            dirty = true
            if measureDir != nil { pendingStamps.append(DragEv(stamp: e.timestamp, applied: now())) }
        } else { handleScroll(dx: e.deltaX, dy: e.deltaY, phase: .changed) }
    }
    override func mouseUp(with e: NSEvent) { if dragging { ds_drag_end(eng) }; dragging = false }

    // ----- frame loop -----
    func frameTick(target: Double, drawable: CAMetalDrawable) {
        let dt = lastTarget > 0 ? max(min(target - lastTarget, 0.1), 1.0 / 240) : 1.0 / 60
        lastTarget = target
        ticksInPhase += 1
        script?.step(self, dt: dt, t: now())
        if glideActive {  // app-owned momentum, exponential decay
            let k = pow(0.94, dt * 60)
            vel = CGPoint(x: vel.x * k, y: vel.y * k)
            let d = CGPoint(x: vel.x * dt, y: vel.y * dt)
            ds_pan(eng, Float(d.x), Float(d.y)); dirty = true
            glideFrames += 1; glideDist += hypot(d.x, d.y)
            if hypot(vel.x, vel.y) < 20 { glideActive = false }
        }
        if dirty { render(tick: target, drawable: drawable) }
    }

    @discardableResult
    func render(tick: Double = 0, png: String? = nil, drawable pre: CAMetalDrawable? = nil) -> Double {
        let t0 = now()
        guard let drawable = pre ?? metalLayer.nextDrawable() else { return -1 }
        let t1 = now()
        let w = Int32(metalLayer.drawableSize.width), h = Int32(metalLayer.drawableSize.height)
        let dev = Unmanaged.passUnretained(device).toOpaque(), q = Unmanaged.passUnretained(queue).toOpaque()
        let tex = Unmanaged.passUnretained(drawable.texture).toOpaque()
        let skiaMs: Double = png != nil ? png!.withCString { ds_render_metal(eng, dev, q, tex, w, h, $0) } : ds_render_metal(eng, dev, q, tex, w, h, nil)
        let cb = queue.makeCommandBuffer()!
        cb.present(drawable)
        let submit = now()
        var zoomCam: [Float] = [0, 0, 0]; ds_get_camera(eng, &zoomCam)
        let f = Frame()
        f.phase = phase; f.idx = frameIdx; f.tick = tick; f.acquireMs = (t1 - t0) * 1e3; f.skiaMs = skiaMs
        f.totalCpuMs = (submit - t0) * 1e3; f.zoom = zoomCam[0]
        frameIdx += 1; framesInPhase += 1
        let stamps = pendingStamps; pendingStamps = []
        let st = store
        for s in stamps { var s = s; s.submitted = submit; st.with { st.drags.append(s) } }
        let first = st.drags.count - stamps.count
        st.with { st.frames.append(f) }
        cb.addCompletedHandler { _ in let d = (now() - submit) * 1e3; st.with { f.gpuDoneMs = d } }
        drawable.addPresentedHandler { d in
            let pt = d.presentedTime
            st.with {
                f.presented = pt
                if stamps.count > 0 { for i in 0..<stamps.count { st.drags[first + i].presented = pt } }
            }
        }
        cb.commit()
        dirty = false
        return skiaMs
    }
}

// ---------- measurement script ----------
final class Script {
    struct P { let name: String; let secs: Double; let begin: (CanvasView) -> Void; let step: (CanvasView, Double, Double) -> Void }
    var phases: [P] = []
    var i = -1, t0 = 0.0, started = false
    var done: () -> Void = {}
    var phaseLog: [(String, Int, Int)] = []  // name, ticks, frames
    var notes: [String] = []

    func step(_ v: CanvasView, dt: Double, t: Double) {
        if !started { started = true; advance(v, t) }
        guard i < phases.count else { return }
        let p = phases[i]
        let el = t - t0
        if el >= p.secs { advance(v, t); return }
        p.step(v, dt, el)
    }
    func advance(_ v: CanvasView, _ t: Double) {
        if i >= 0 { phaseLog.append((phases[i].name, v.ticksInPhase, v.framesInPhase)) }
        i += 1
        if i >= phases.count { v.script = nil; done(); return }
        t0 = t; v.phase = phases[i].name; v.ticksInPhase = 0; v.framesInPhase = 0
        phases[i].begin(v)
    }
}

func buildScript(_ v: CanvasView, out: String, finish: @escaping () -> Void) -> Script {
    let s = Script()
    let e = v.eng!
    let fit = ds_fit_zoom(e)
    let cx = Float(v.bounds.width / 2), cy = Float(v.bounds.height / 2)
    // scripted camera paths: pan at three zooms (0.3 / 1 / 4), 3 s each, 2400 pt/s peak
    for z in [Float(0.3), 1.0, 4.0] {
        s.phases.append(.init(name: "pan@\(z)", secs: 3, begin: { v in ds_set_camera(e, z, -1500 * z, -1200 * z); v.dirty = true }, step: { v, dt, el in
            let a = Float(el) * 2 * .pi / 3
            ds_set_camera(e, z, (-1500 + 1200 * sin(a)) * z, (-1200 + 900 * sin(a * 1.7)) * z); v.dirty = true
        }))
    }
    // pinch zoom through handleMagnify (the pinch recogniser's handler): fit -> 800% -> fit, anchored at view centre
    s.phases.append(.init(name: "zoom", secs: 10, begin: { v in ds_set_camera(e, fit, 20, 20); v.dirty = true }, step: { v, dt, el in
        let dir: Double = el < 5 ? 1 : -1
        let rate = log(Double(8.0 / fit)) / 5.0
        v.handleMagnify(CGFloat(exp(rate * dir * dt) - 1), at: CGPoint(x: CGFloat(cx), y: CGFloat(cy)))
    }))
    // two-finger scroll flicks at 100%; first with momentum, then with the app's Reduce Motion flag on
    for rm in [false, true] {
        var tailStart = 0.0, panAtEnd: [Float] = [0, 0, 0], distAfter = 0.0
        s.phases.append(.init(name: rm ? "scroll-reduce-motion-on" : "scroll-reduce-motion-off", secs: 6, begin: { v in
            v.reduceMotion = rm; ds_set_camera(e, 1, -1000, -1000); v.dirty = true; tailStart = 0; v.glideActive = false
        }, step: { v, dt, el in
            // 3 flicks, each: began, 0.25 s of 60 pt/event @120 Hz (7200 pt/s), ended, then 1.75 s tail
            let k = el.truncatingRemainder(dividingBy: 2.0), n = Int(el / 2.0)
            if n < 3 {
                if k < dt { v.handleScroll(dx: 0, dy: 0, phase: .began) }
                if k < 0.25 { v.handleScroll(dx: -20, dy: -60, phase: .changed, dt: dt) }
                else if tailStart != Double(n + 1) {
                    tailStart = Double(n + 1); v.handleScroll(dx: 0, dy: 0, phase: .ended)
                    ds_get_camera(e, &panAtEnd); distAfter = 0
                    if n == 2 { s.notes.append("\(rm ? "RM on " : "RM off") flick end: glideActive=\(v.glideActive)") }
                }
            }
            if n == 2, k > 1.9 {
                var c: [Float] = [0, 0, 0]; ds_get_camera(e, &c)
                distAfter = Double(hypot(c[1] - panAtEnd[1], c[2] - panAtEnd[2]))
                if k > 1.9 && !s.notes.contains(where: { $0.hasPrefix("tail \(rm)") }) {
                    s.notes.append("tail \(rm) travel after finger lift: \(String(format: "%.0f", distAfter)) pt, glide frames \(v.glideFrames)")
                }
            }
        }))
    }
    // drag: real NSEvents (mouseDown, ~270 mouseDragged/s at a period unrelated to vsync, mouseUp) posted to the app queue
    var timer: DispatchSourceTimer?
    var startCenter: [Float] = [0, 0]
    var path: (Double) -> CGPoint = { _ in .zero }
    s.phases.append(.init(name: "drag", secs: 5, begin: { v in
        v.reduceMotion = false
        ds_set_camera(e, 1, 0, 0)
        ds_card_center(e, 4, &startCenter)
        let z: Float = 1
        let px = CGFloat(startCenter[0] * z), py = CGFloat(startCenter[1] * z)
        ds_set_camera(e, z, Float(v.bounds.width / 2) - Float(px), Float(v.bounds.height / 2) - Float(py)); v.dirty = true
        let c = CGPoint(x: v.bounds.width / 2, y: v.bounds.height / 2)
        path = { t in CGPoint(x: c.x + 220 * sin(t * 2.0), y: c.y + 140 * sin(t * 3.1)) }
        func post(_ type: NSEvent.EventType, _ p: CGPoint) {
            let wp = v.convert(p, to: nil)
            let ev = NSEvent.mouseEvent(with: type, location: wp, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: v.window!.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 1)!
            NSApp.postEvent(ev, atStart: false)
        }
        post(.leftMouseDown, c)
        let tt = DispatchSource.makeTimerSource(queue: .main)
        let t0 = now()
        tt.schedule(deadline: .now() + 0.01, repeating: .microseconds(3700), leeway: .microseconds(200))
        tt.setEventHandler { postedDrags += 1; post(.leftMouseDragged, path(now() - t0)) }
        tt.resume(); timer = tt
    }, step: { _, _, _ in }))
    s.phases.append(.init(name: "drag-release", secs: 0.3, begin: { v in
        timer?.cancel(); timer = nil
        let p = path(5.0)
        let wp = v.convert(p, to: nil)
        NSApp.postEvent(NSEvent.mouseEvent(with: .leftMouseUp, location: wp, modifierFlags: [], timestamp: ProcessInfo.processInfo.systemUptime, windowNumber: v.window!.windowNumber, context: nil, eventNumber: 0, clickCount: 1, pressure: 0)!, atStart: false)
    }, step: { _, _, _ in }))
    s.phases.append(.init(name: "drag-verify", secs: 0.2, begin: { v in
        var c: [Float] = [0, 0]; ds_card_center(e, 4, &c)
        let last = path(5.0)  // pointer at the last drag position (approx: last posted sample)
        let grabOffsetFree = (Double(c[0]) - Double(startCenter[0]), Double(c[1]) - Double(startCenter[1]))
        s.notes.append("drag events posted \(postedDrags) received \(gotDrags)")
        s.notes.append(String(format: "drag: card moved by (%.1f, %.1f) pt for a pointer path ending near (%.1f, %.1f) from centre; re-record per move %.3f ms", grabOffsetFree.0, grabOffsetFree.1, last.x - v.bounds.width / 2, last.y - v.bounds.height / 2, ds_last_rerecord_ms(e)))
    }, step: { _, _, _ in }))
    // idle: nothing changes; frames rendered must stay 0
    s.phases.append(.init(name: "idle", secs: 3, begin: { _ in }, step: { _, _, _ in }))
    s.done = { finish() }
    return s
}

// ---------- app ----------
final class AppDelegate: NSObject, NSApplicationDelegate {
    var window: NSWindow!
    var view: CanvasView!
    func applicationDidFinishLaunching(_ n: Notification) {
        view = CanvasView(frame: NSRect(x: 0, y: 0, width: 1280, height: 800))
        window = NSWindow(contentRect: view.frame, styleMask: [.titled, .closable, .resizable, .miniaturizable], backing: .buffered, defer: false)
        window.title = "Design spike"
        window.contentView = view
        window.center()
        view.eng = fontPath.withCString { ds_new($0) }
        view.reduceMotion = rmArg.map { $0 == "on" } ?? NSWorkspace.shared.accessibilityDisplayShouldReduceMotion
        window.makeKeyAndOrderFront(nil)
        window.makeFirstResponder(view)
        NSApp.activate(ignoringOtherApps: true)
        view.syncSize()
        let mag = NSMagnificationGestureRecognizer(target: self, action: #selector(pinch(_:)))
        view.addGestureRecognizer(mag)
        ds_set_camera(view.eng, ds_fit_zoom(view.eng), 20, 20)
        if measureDir != nil {  // warm-up (pipeline/shader compile) before the display link owns the layer
            let v = view!
            v.phase = "warmup"
            for (z, px, py) in [(ds_fit_zoom(v.eng), Float(20), Float(20)), (0.3, -450, -360), (1, -1000, -1100), (4, -4500, -4400)] {
                ds_set_camera(v.eng, z, px, py); v.render()
            }
            ds_set_camera(v.eng, ds_fit_zoom(v.eng), 20, 20)
        }
        view.startLink()
        if noLod { ds_set_lod(view.eng, 0) }
        if let b = barsMaxW { ds_set_bars_max_w(view.eng, b) }
        if let b = blurMinW { ds_set_blur_min_w(view.eng, b) }
        if let dir = benchDir {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.0) { runBench(self.view, dir) }
        } else if let dir = measureDir {
            try? FileManager.default.createDirectory(atPath: dir, withIntermediateDirectories: true)
            DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { self.runMeasure(dir) }
        }
    }
    @objc func pinch(_ g: NSMagnificationGestureRecognizer) {
        view.handleMagnify(g.magnification, at: g.location(in: view)); g.magnification = 0
    }
    func applicationShouldTerminateAfterLastWindowClosed(_ a: NSApplication) -> Bool { true }

    func runMeasure(_ dir: String) {
        let v = view!
        let sc = buildScript(v, out: dir) { [self] in
            // let the last presented handlers land, then snapshots + report
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { self.finish(dir) }
        }
        v.script = sc
        scriptRef = sc
    }
    var scriptRef: Script?

    func finish(_ dir: String) {
        let v = view!, e = v.eng!, sc = scriptRef!
        v.link?.invalidate()
        // ---- snapshots: Metal PNG + CPU-raster PNG of the same camera (diffed offline) ----
        let w = Int32(v.metalLayer.drawableSize.width), h = Int32(v.metalLayer.drawableSize.height)
        let fit = ds_fit_zoom(e)
        let cams: [(String, Float, Float, Float)] = [("fit", fit, 20, 20), ("z25", 0.25, -300, -200), ("z100", 1, -1000, -1100), ("z400", 4, -4500, -4400),
                                                     ("z10", 0.10, 20, 20), ("z800", 8, -140, -220)]
        for (n, z, px, py) in cams {
            ds_set_camera(e, z, px, py)
            v.render(png: "\(dir)/metal-\(n).png")
            _ = ds_render_cpu_png(e, w, h, "\(dir)/maccpu-\(n).png")
        }
        // ---- stats ----
        let all = v.store.with { v.store.frames }
        var csv = "phase,frame,zoom,acquire_ms,skia_encode_submit_ms,cpu_total_ms,gpu_done_ms,present_interval_ms\n"
        var prevPresent = 0.0
        var byPhase: [String: [Frame]] = [:]
        var intervals: [String: [Double]] = [:]
        for f in all {
            var iv = 0.0
            if f.presented > 0, prevPresent > 0 { iv = (f.presented - prevPresent) * 1e3 }
            if f.presented > 0 { prevPresent = f.presented }
            csv += "\(f.phase),\(f.idx),\(f.zoom),\(String(format: "%.3f,%.3f,%.3f,%.3f,%.3f", f.acquireMs, f.skiaMs, f.totalCpuMs, f.gpuDoneMs, iv))\n"
            byPhase[f.phase, default: []].append(f)
            // intervals only count when consecutive frames are in a continuously animating phase
            if iv > 0, iv < 100 { intervals[f.phase, default: []].append(iv) }
        }
        try? csv.write(toFile: "\(dir)/frames.csv", atomically: true, encoding: .utf8)
        var dcsv = "event_to_applied_ms,event_to_submit_ms,event_to_present_ms\n"
        var e2s: [Double] = [], e2p: [Double] = [], e2a: [Double] = []
        for d in v.store.drags where d.presented > 0 {
            let a = (d.applied - d.stamp) * 1e3, s = (d.submitted - d.stamp) * 1e3, p = (d.presented - d.stamp) * 1e3
            e2a.append(a); e2s.append(s); e2p.append(p)
            dcsv += String(format: "%.3f,%.3f,%.3f\n", a, s, p)
        }
        try? dcsv.write(toFile: "\(dir)/drag-latency.csv", atomically: true, encoding: .utf8)

        var out = "# measure summary\n"
        out += "display refresh: \(v.window?.screen?.maximumFramesPerSecond ?? 0) Hz max; system Reduce Motion = \(NSWorkspace.shared.accessibilityDisplayShouldReduceMotion); backing scale \(v.scale)\n"
        var cnt: [UInt32] = [0, 0, 0]; ds_counts(e, &cnt)
        out += "scene: nodes=\(cnt[0]) text_runs=\(cnt[1]) glass=\(cnt[2]); doc open (taffy layout + paragraphs + 100 SkPictures) = \(String(format: "%.1f", ds_open_ms(e))) ms (taffy layout part \(String(format: "%.1f", ds_layout_ms(e))) ms)\n"
        out += "resident (phys_footprint) at end: \(String(format: "%.0f", residentMB())) MB\n\n"
        out += "phase | frames | cpu_total p50/p95/p99/max ms | skia encode+submit p50/p95/p99 | gpu_done p50/p95/p99 | present interval p50/p95/p99 (ms) | % intervals <= 9.0 ms\n"
        for name in byPhase.keys.sorted() {
            let fs = byPhase[name]!
            let cpu = fs.map { $0.totalCpuMs }, sk = fs.map { $0.skiaMs }, gp = fs.map { $0.gpuDoneMs }
            let iv = intervals[name] ?? []
            let ok = iv.isEmpty ? 0 : 100 * Double(iv.filter { $0 <= 9.0 }.count) / Double(iv.count)
            out += String(format: "%@ | %d | %.2f/%.2f/%.2f/%.2f | %.2f/%.2f/%.2f | %.2f/%.2f/%.2f | %.2f/%.2f/%.2f | %.1f%%\n", name, fs.count, pct(cpu, 0.5), pct(cpu, 0.95), pct(cpu, 0.99), cpu.max() ?? 0, pct(sk, 0.5), pct(sk, 0.95), pct(sk, 0.99), pct(gp, 0.5), pct(gp, 0.95), pct(gp, 0.99), pct(iv, 0.5), pct(iv, 0.95), pct(iv, 0.99), ok)
        }
        let anim = all.filter { $0.phase.hasPrefix("pan") || $0.phase == "zoom" }
        let ac = anim.map { $0.totalCpuMs }, ag = anim.map { $0.gpuDoneMs }
        let aiv = anim.map { $0.phase }.isEmpty ? [] : Array(intervals.filter { $0.key.hasPrefix("pan") || $0.key == "zoom" }.values.joined())
        out += String(format: "\nPAN+ZOOM ALL (%d frames): cpu_total p50 %.2f p95 %.2f p99 %.2f | gpu_done p50 %.2f p95 %.2f p99 %.2f | present interval p50 %.2f p95 %.2f p99 %.2f\n", anim.count, pct(ac, 0.5), pct(ac, 0.95), pct(ac, 0.99), pct(ag, 0.5), pct(ag, 0.95), pct(ag, 0.99), pct(aiv, 0.5), pct(aiv, 0.95), pct(aiv, 0.99))
        out += String(format: "DRAG (%d events): event->applied p50 %.2f p95 %.2f | event->submit p50 %.2f p95 %.2f p99 %.2f | event->present p50 %.2f p95 %.2f p99 %.2f ms\n", e2p.count, pct(e2a, 0.5), pct(e2a, 0.95), pct(e2s, 0.5), pct(e2s, 0.95), pct(e2s, 0.99), pct(e2p, 0.5), pct(e2p, 0.95), pct(e2p, 0.99))
        out += "\nphase ticks vs frames rendered:\n"
        for (n, t, f) in sc.phaseLog { out += "  \(n): ticks \(t), frames \(f)\n" }
        out += "\nnotes:\n" + sc.notes.map { "  " + $0 }.joined(separator: "\n") + "\n"
        try? out.write(toFile: "\(dir)/summary.txt", atomically: true, encoding: .utf8)
        print(out)
        ds_free(e)
        NSApp.terminate(nil)
    }
}

// ---------- uncapped bench: same camera paths, simulated 120 Hz steps, offscreen target, serial (CPU+GPU) frame cost ----------
func runBench(_ v: CanvasView, _ dir: String) {
    v.link?.invalidate()
    let e = v.eng!
    let w = Int(v.metalLayer.drawableSize.width), h = Int(v.metalLayer.drawableSize.height)
    let d = MTLTextureDescriptor.texture2DDescriptor(pixelFormat: .bgra8Unorm, width: w, height: h, mipmapped: false)
    d.usage = [.renderTarget, .shaderRead]; d.storageMode = .private
    let tex = v.device.makeTexture(descriptor: d)!
    let dev = Unmanaged.passUnretained(v.device).toOpaque(), q = Unmanaged.passUnretained(v.queue).toOpaque()
    let tp = Unmanaged.passUnretained(tex).toOpaque()
    let fit = ds_fit_zoom(e)
    let cx = Float(v.bounds.width / 2), cy = Float(v.bounds.height / 2)
    func frame() -> (Double, Double) {
        let t0 = now()
        let sk = ds_render_metal(e, dev, q, tp, Int32(w), Int32(h), nil)
        let cb = v.queue.makeCommandBuffer()!
        cb.commit(); cb.waitUntilCompleted()  // same serial queue: completes after Skia's work
        return (sk, (now() - t0) * 1e3)
    }
    var rows: [(String, Double, Double)] = []
    var csv = "phase,frame,skia_encode_submit_ms,serial_total_ms\n"
    func run(_ name: String, frames: Int, setup: () -> Void, step: (Int) -> Void) {
        setup(); for _ in 0..<5 { _ = frame() }  // warm-up
        var n = 0
        for i in 0..<frames {
            step(i)
            let (a, b) = frame()
            rows.append((name, a, b)); csv += "\(name),\(n),\(String(format: "%.3f,%.3f", a, b))\n"; n += 1
        }
    }
    for z in [Float(0.3), 1.0, 4.0] {
        run("pan@\(z)", frames: 360, setup: { ds_set_camera(e, z, -1500 * z, -1200 * z) }) { i in
            let a = Float(i) / 120 * 2 * .pi / 3
            ds_set_camera(e, z, (-1500 + 1200 * sin(a)) * z, (-1200 + 900 * sin(a * 1.7)) * z)
        }
    }
    run("zoom", frames: 1200, setup: { ds_set_camera(e, fit, 20, 20) }) { i in
        let dir: Double = i < 600 ? 1 : -1
        ds_zoom_at(e, Float(exp(log(Double(8.0 / fit)) / 5.0 * dir / 120)), cx, cy)
    }
    for z in [Float(0.10), fit, 0.25, 0.4, 0.6, 1, 2, 4, 8] {
        run("static@\(String(format: "%.2f", z))", frames: 60, setup: { ds_set_camera(e, z, -1000 * z, -1100 * z) }) { _ in }
    }
    var c: [Float] = [0, 0]; ds_card_center(e, 4, &c)
    run("drag", frames: 600, setup: {
        ds_set_camera(e, 1, cx - c[0], cy - c[1]); _ = ds_drag_begin(e, cx, cy)
    }) { i in
        let t = Double(i) / 120
        ds_drag_move(e, cx + 220 * Float(sin(t * 2)), cy + 140 * Float(sin(t * 3.1)))
    }
    ds_drag_end(e)
    try? csv.write(toFile: "\(dir)/bench-frames.csv", atomically: true, encoding: .utf8)
    var out = "# bench summary (offscreen \(w)x\(h), simulated 120 Hz steps, serial CPU+GPU frame cost; lod=\(noLod ? "off" : "on"), blur_min_w=\(blurMinW.map { String($0) } ?? "250"), bars_max_w=\(barsMaxW.map { String($0) } ?? "150")), budget 8.33 ms\n"
    out += "phase | frames | serial_total p50/p95/p99/max ms | skia encode+submit p50/p95/p99 ms | over 8.33 ms\n"
    var seen: [String] = []
    for r in rows where !seen.contains(r.0) { seen.append(r.0) }
    for n in seen {
        let a = rows.filter { $0.0 == n }.map { $0.1 }, b = rows.filter { $0.0 == n }.map { $0.2 }
        out += String(format: "%@ | %d | %.2f/%.2f/%.2f/%.2f | %.2f/%.2f/%.2f | %d\n", n, b.count, pct(b, 0.5), pct(b, 0.95), pct(b, 0.99), b.max() ?? 0, pct(a, 0.5), pct(a, 0.95), pct(a, 0.99), b.filter { $0 > 8.33 }.count)
    }
    let anim = rows.filter { $0.0.hasPrefix("pan") || $0.0 == "zoom" }.map { $0.2 }
    out += String(format: "\nPAN+ZOOM ALL (%d frames): serial total p50 %.2f p95 %.2f p99 %.2f max %.2f; over budget %.2f%%\n", anim.count, pct(anim, 0.5), pct(anim, 0.95), pct(anim, 0.99), anim.max() ?? 0, 100 * Double(anim.filter { $0 > 8.33 }.count) / Double(anim.count))
    out += "resident at end: \(String(format: "%.0f", residentMB())) MB\n"
    try? out.write(toFile: "\(dir)/bench-summary.txt", atomically: true, encoding: .utf8)
    print(out)
    NSApp.terminate(nil)
}

let app = NSApplication.shared
app.setActivationPolicy(.regular)
let delegate = AppDelegate()
app.delegate = delegate
app.run()

extension CanvasView: CAMetalDisplayLinkDelegate {
    func metalDisplayLink(_ link: CAMetalDisplayLink, needsUpdate update: CAMetalDisplayLink.Update) {
        frameTick(target: update.targetTimestamp, drawable: update.drawable)
    }
}
