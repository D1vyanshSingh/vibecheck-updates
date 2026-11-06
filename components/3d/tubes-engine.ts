import * as THREE from "three";

/**
 * The original effect is a CDN-only `threejs-components` build with no exposed
 * teardown, no resize handling and no palette control — it randomises colours on
 * click, which would fight this design. This is a local, controlled re-creation:
 * the same idea (cursor-reactive tubes in depth, violet illumination) built on
 * plain Three.js so it can be disposed, paused and themed safely.
 */

type Options = {
  /** 3 on desktop, 2 on small screens. */
  density?: number;
  /** Lower quality for narrow viewports. */
  quality?: "high" | "low";
};

export type TubesSceneHandle = {
  dispose: () => void;
};

const POINT_COUNT = 24;
const SEGMENTS = 44;
const RADIAL_SEGMENTS = 7;
const SPACING = 0.62;

const TUBE_COLORS = ["#702bff", "#974fff", "#5a20d8", "#c9b5ff"];
const HEAD_COLORS = ["#c9b5ff", "#974fff", "#702bff"];

type Snake = {
  points: THREE.Vector3[];
  curve: THREE.CatmullRomCurve3;
  mesh: THREE.Mesh;
  geometry: THREE.TubeGeometry;
  material: THREE.MeshStandardMaterial;
  head: THREE.Mesh;
  headMaterial: THREE.MeshBasicMaterial;
  radius: number;
  phase: number;
  offset: THREE.Vector2;
};

export function createTubesScene(
  canvas: HTMLCanvasElement,
  options: Options = {},
): TubesSceneHandle | null {
  const density = Math.max(2, Math.min(options.density ?? 3, 5));
  const lowQuality = options.quality === "low";

  let renderer: THREE.WebGLRenderer;
  try {
    renderer = new THREE.WebGLRenderer({
      canvas,
      antialias: !lowQuality,
      alpha: false,
      powerPreference: "high-performance",
    });
  } catch {
    return null;
  }

  const scene = new THREE.Scene();
  scene.background = new THREE.Color(0x08080d);
  scene.fog = new THREE.FogExp2(0x08080d, 0.026);

  const camera = new THREE.PerspectiveCamera(44, 1, 0.1, 120);
  camera.position.set(0, 0, 21);

  const stage = new THREE.Group();
  scene.add(stage);

  scene.add(new THREE.AmbientLight(0x3a2566, 1.1));
  const key = new THREE.PointLight(0x974fff, 90, 60, 2);
  key.position.set(8, 7, 14);
  scene.add(key);
  const rim = new THREE.PointLight(0xc9b5ff, 45, 50, 2);
  rim.position.set(-10, -8, 8);
  scene.add(rim);

  const pointer = new THREE.Vector2(0, 0);
  const smoothPointer = new THREE.Vector2(0, 0);
  const autoMotion = new THREE.Vector2(0, 0);
  const hoverCapable =
    typeof window !== "undefined" &&
    window.matchMedia("(hover: hover) and (pointer: fine)").matches;

  const snakes: Snake[] = [];

  for (let index = 0; index < density; index += 1) {
    const color = new THREE.Color(TUBE_COLORS[index % TUBE_COLORS.length]);
    const radius = 0.38 + (index % 3) * 0.1;
    const points = Array.from({ length: POINT_COUNT }, (_, pointIndex) =>
      new THREE.Vector3(
        Math.sin(index + pointIndex * 0.3) * 2,
        Math.cos(index + pointIndex * 0.32) * 1.4,
        -pointIndex * SPACING * 0.4,
      ),
    );

    const curve = new THREE.CatmullRomCurve3(points, false, "catmullrom", 0.4);
    const geometry = new THREE.TubeGeometry(curve, SEGMENTS, radius, RADIAL_SEGMENTS, false);
    const material = new THREE.MeshStandardMaterial({
      color: 0x0a0616,
      emissive: color,
      emissiveIntensity: 1.6,
      roughness: 0.34,
      metalness: 0.18,
      transparent: true,
      opacity: 0.94,
    });
    const mesh = new THREE.Mesh(geometry, material);
    mesh.frustumCulled = false;

    const headMaterial = new THREE.MeshBasicMaterial({
      color: new THREE.Color(HEAD_COLORS[index % HEAD_COLORS.length]),
      transparent: true,
      opacity: 0.9,
      blending: THREE.AdditiveBlending,
      depthWrite: false,
    });
    const head = new THREE.Mesh(new THREE.SphereGeometry(radius * 1.9, 16, 16), headMaterial);
    head.position.copy(points[0]);
    head.frustumCulled = false;

    stage.add(mesh);
    stage.add(head);

    snakes.push({
      points,
      curve,
      mesh,
      geometry,
      material,
      head,
      headMaterial,
      radius,
      phase: index * 1.7,
      offset: new THREE.Vector2(
        density === 2 ? (index - 0.5) * 3.4 : (index - (density - 1) / 2) * 3.6,
        Math.sin(index * 1.3) * 1.6,
      ),
    });
  }

  // Sparse lavender dust for depth.
  const dustCount = lowQuality ? 70 : 150;
  const dustPositions = new Float32Array(dustCount * 3);
  for (let index = 0; index < dustCount; index += 1) {
    dustPositions[index * 3] = (Math.random() - 0.5) * 46;
    dustPositions[index * 3 + 1] = (Math.random() - 0.5) * 30;
    dustPositions[index * 3 + 2] = -Math.random() * 34 + 4;
  }
  const dustGeometry = new THREE.BufferGeometry();
  dustGeometry.setAttribute("position", new THREE.BufferAttribute(dustPositions, 3));
  const dustMaterial = new THREE.PointsMaterial({
    color: new THREE.Color("#c9b5ff"),
    size: 0.07,
    transparent: true,
    opacity: 0.42,
    sizeAttenuation: true,
    depthWrite: false,
    blending: THREE.AdditiveBlending,
  });
  const dust = new THREE.Points(dustGeometry, dustMaterial);
  stage.add(dust);

  let width = 1;
  let height = 1;

  const resize = () => {
    const parent = canvas.parentElement;
    width = Math.max(1, parent?.clientWidth ?? window.innerWidth);
    height = Math.max(1, parent?.clientHeight ?? window.innerHeight);
    renderer.setPixelRatio(
      Math.min(window.devicePixelRatio || 1, lowQuality ? 1.5 : 1.85),
    );
    renderer.setSize(width, height, false);
    camera.aspect = width / height;
    // Widen the field of view on tight viewports so tubes stay in frame.
    camera.fov = width < 720 ? 58 : 44;
    camera.updateProjectionMatrix();
  };

  resize();

  const observer = new ResizeObserver(resize);
  if (canvas.parentElement) observer.observe(canvas.parentElement);
  window.addEventListener("resize", resize, { passive: true });

  const onPointerMove = (event: PointerEvent) => {
    if (event.pointerType === "touch") return;
    pointer.set(
      (event.clientX / window.innerWidth) * 2 - 1,
      -((event.clientY / window.innerHeight) * 2 - 1),
    );
  };

  if (hoverCapable) {
    window.addEventListener("pointermove", onPointerMove, { passive: true });
  }

  const clock = new THREE.Clock();
  let frame = 0;
  let geometryAccumulator = 0;
  let paused = false;
  let disposed = false;

  const onVisibility = () => {
    paused = document.hidden;
    if (!paused) clock.getDelta();
  };
  document.addEventListener("visibilitychange", onVisibility);

  const updateSnake = (snake: Snake, time: number, dt: number, index: number) => {
    const spreadX = width < 720 ? 7 : 11;
    const spreadY = width < 720 ? 5 : 6.4;

    const driftX = hoverCapable ? 0 : Math.sin(time * 0.32 + snake.phase) * 4.2;
    const driftY = hoverCapable ? 0 : Math.cos(time * 0.27 + snake.phase * 1.4) * 2.6;

    autoMotion.set(driftX + snake.offset.x, driftY + snake.offset.y);

    const headTargetX = smoothPointer.x * spreadX + autoMotion.x;
    const headTargetY = smoothPointer.y * spreadY + autoMotion.y;
    const headTargetZ = 6 - index * 2.1 + Math.sin(time * 0.5 + snake.phase) * 0.6;

    const head = snake.points[0];
    const headEase = 1 - Math.pow(0.0015, dt);
    head.x += (headTargetX - head.x) * headEase;
    head.y += (headTargetY - head.y) * headEase;
    head.z += (headTargetZ - head.z) * headEase * 0.6;

    for (let pointIndex = 1; pointIndex < snake.points.length; pointIndex += 1) {
      const current = snake.points[pointIndex];
      const previous = snake.points[pointIndex - 1];
      const direction = new THREE.Vector3().subVectors(current, previous);
      if (direction.lengthSq() === 0) direction.set(0.01, 0.01, 0.01);
      direction.normalize();
      const target = previous.clone().addScaledVector(direction, -SPACING);
      const ease = 1 - Math.pow(0.00006 + pointIndex * 0.00003, dt);
      current.lerp(target, Math.min(1, ease));
      current.z += Math.sin(time * 0.6 + pointIndex * 0.4 + snake.phase) * 0.0016;
    }

    snake.head.position.copy(head);
  };

  const rebuildGeometry = (snake: Snake) => {
    const next = new THREE.TubeGeometry(
      snake.curve,
      SEGMENTS,
      snake.radius,
      RADIAL_SEGMENTS,
      false,
    );
    snake.mesh.geometry = next;
    snake.geometry.dispose();
    snake.geometry = next;
  };

  const render = () => {
    if (disposed) return;
    frame = requestAnimationFrame(render);
    if (paused) return;

    const dt = Math.min(clock.getDelta(), 0.05);
    const time = clock.elapsedTime;

    smoothPointer.lerp(pointer, 1 - Math.pow(0.006, dt));

    stage.rotation.x += (smoothPointer.y * 0.085 - stage.rotation.x) * 0.04;
    stage.rotation.y += (smoothPointer.x * 0.12 - stage.rotation.y) * 0.04;
    stage.rotation.z += (smoothPointer.x * -0.02 - stage.rotation.z) * 0.03;

    snakes.forEach((snake, index) => updateSnake(snake, time, dt, index));

    geometryAccumulator += dt;
    if (geometryAccumulator >= 1 / 45) {
      geometryAccumulator = 0;
      snakes.forEach(rebuildGeometry);
    }

    dust.rotation.y = time * 0.012;

    renderer.render(scene, camera);
  };

  frame = requestAnimationFrame(render);

  canvas.style.opacity = "0";
  canvas.style.transition = "opacity 900ms ease";
  requestAnimationFrame(() => {
    canvas.style.opacity = "1";
  });

  return {
    dispose: () => {
      if (disposed) return;
      disposed = true;
      cancelAnimationFrame(frame);
      observer.disconnect();
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onPointerMove);
      document.removeEventListener("visibilitychange", onVisibility);
      snakes.forEach((snake) => {
        snake.mesh.geometry.dispose();
        snake.material.dispose();
        snake.head.geometry.dispose();
        snake.headMaterial.dispose();
        stage.remove(snake.mesh);
        stage.remove(snake.head);
      });
      dustGeometry.dispose();
      dustMaterial.dispose();
      stage.remove(dust);
      scene.clear();
      renderer.dispose();
      renderer.forceContextLoss();
    },
  };
}
