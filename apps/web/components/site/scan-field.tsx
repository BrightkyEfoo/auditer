"use client";

import { useEffect, useRef } from "react";

/**
 * Le champ de balayage — la seule pièce de mouvement majeure du site vitrine.
 *
 * CE QUE C'EST. Un treillis de nœuds en trois dimensions, projeté en
 * perspective réelle sur un canvas 2D, traversé de bas en haut par un plan de
 * balayage. Un nœud proche du plan s'allume en acide et se relie en filaire à
 * ses voisins immédiats ; au-delà, il retombe au gris de la grille. Le scroll
 * pilote deux choses : la rotation de la structure et l'avancée de la caméra
 * dans la profondeur. Descendre la page, c'est traverser le treillis.
 *
 * POURQUOI CETTE FORME. La direction artistique du site est une fiche
 * technique de laboratoire. Une sphère lustrée ou un blob dégradé — la 3D par
 * défaut — la contredirait frontalement. Un treillis filaire balayé dit ce que
 * fait le produit : parcourir une structure, mesurer, marquer ce qui ressort.
 * La forme sert le propos, sinon elle n'est qu'une démonstration technique.
 *
 * POURQUOI PAS THREE.JS. Le besoin ici est de projeter quelques centaines de
 * points et de tracer des segments. Une matrice de rotation et une division
 * font le travail en une quarantaine de lignes ; three.js coûterait environ
 * 150 Ko compressés pour le même rendu, sur un site qui en pèse 756 au total —
 * et l'allègement des bundles était une demande explicite. WebGL se justifie
 * au-delà de quelques milliers de points dessinés un à un, ou pour un effet par
 * pixel. Ce n'est pas le cas.
 *
 * CE QU'IL NE FAIT PAS. Aucune allocation dans la boucle : positions et état
 * vivent dans des `Float32Array` alloués une fois. Aucun `getImageData`, aucun
 * `shadowBlur` par frame. La boucle s'arrête hors viewport et onglet caché.
 * Sous `prefers-reduced-motion`, une seule image est rendue puis plus rien :
 * le visuel demeure, le mouvement cesse.
 */

/* ── Paramètres macro. C'est ici que se joue le caractère ; le reste est
      mécanique et ne bouge plus une fois calé. ─────────────────────────── */

/** Densité cible. Plafonnée ensuite par la surface réelle et le type de
 *  pointeur — un mobile n'a ni la surface ni le budget d'un écran de bureau. */
const NODE_TARGET = 320;

/** Demi-étendue du treillis en unités de monde, sur les trois axes. */
const SPREAD = 260;

/** Distance focale. Plus elle est courte, plus la perspective est marquée. */
const FOV = 420;

/** Demi-épaisseur de la bande de balayage, en fraction de la hauteur du
 *  viewport. Une bande trop fine clignote, une bande trop épaisse allume tout
 *  et ne balaye plus rien. */
const SWEEP_BAND = 0.22;

/** Distance maximale entre deux nœuds pour qu'un segment les relie. Au carré :
 *  la boucle compare des carrés et évite autant de racines.
 *
 *  Réglée à la baisse après lecture d'une capture : à 78, le maillage passait
 *  en plein dans la colonne de texte et gênait la lecture. Un fond génératif
 *  qui rivalise avec le contenu est raté, quelle que soit sa qualité. */
const LINK_DIST_SQ = 58 * 58;

const ACID = "198, 255, 74";
const GRID = "110, 122, 125";

/** Bruit de valeur seedé — pas de `Math.random()`.
 *
 *  Deux raisons. La composition doit être REPRODUCTIBLE : le même rendu à
 *  chaque chargement, sinon on ne peut pas juger un réglage. Et une position
 *  tirée au hasard uniforme donne un nuage plat ; une fonction de bruit donne
 *  des amas et des vides, c'est-à-dire une structure. */
function hash(i: number, salt: number): number {
  const x = Math.sin(i * 127.1 + salt * 311.7) * 43758.5453;
  return x - Math.floor(x);
}

export function ScanField() {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const coarse = window.matchMedia("(pointer: coarse)").matches;

    const dpr = Math.min(window.devicePixelRatio || 1, 2);
    let w = 0;
    let h = 0;

    const resize = (): void => {
      const r = canvas.getBoundingClientRect();
      w = r.width;
      h = r.height;
      canvas.width = Math.round(w * dpr);
      canvas.height = Math.round(h * dpr);
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };
    const ro = new ResizeObserver(resize);
    ro.observe(canvas);
    resize();

    /* ── Le treillis, alloué une fois ─────────────────────────────────── */
    const count = Math.max(
      90,
      Math.min(coarse ? 130 : NODE_TARGET, Math.floor((w * h) / 5200)),
    );
    const wx = new Float32Array(count);
    const wy = new Float32Array(count);
    const wz = new Float32Array(count);
    // Tampons de projection, réécrits à chaque frame sans réallocation.
    const px = new Float32Array(count);
    const py = new Float32Array(count);
    const scale = new Float32Array(count);
    const lit = new Float32Array(count);

    for (let i = 0; i < count; i++) {
      // `pow(u, 1.6)` concentre les nœuds vers le centre : une distribution
      // uniforme donnerait un pavé régulier, qui lit comme un motif et non
      // comme une structure.
      const u = hash(i, 1);
      const r = Math.pow(u, 1.6) * SPREAD;
      const theta = hash(i, 2) * Math.PI * 2;
      const phi = Math.acos(2 * hash(i, 3) - 1);
      wx[i] = r * Math.sin(phi) * Math.cos(theta);
      wy[i] = (hash(i, 4) - 0.5) * SPREAD * 2.4;
      wz[i] = r * Math.cos(phi);
    }

    /* ── Progression du scroll, lissée ────────────────────────────────── */
    let scrollTarget = 0;
    let scrollEased = 0;

    const readScroll = (): void => {
      const max = document.documentElement.scrollHeight - window.innerHeight;
      // `scrollY` ne force pas de recalcul de mise en page, contrairement à un
      // getBoundingClientRect par frame.
      scrollTarget = max > 0 ? Math.min(1, Math.max(0, window.scrollY / max)) : 0;
    };
    readScroll();
    scrollEased = scrollTarget;

    const draw = (): void => {
      ctx.clearRect(0, 0, w, h);

      const cx = w * 0.5;
      const cy = h * 0.5;

      // Le scroll fait tourner la structure d'un tiers de tour et avance la
      // caméra dans la profondeur. Deux gestes seulement : au-delà, le lecteur
      // ne relie plus son geste à ce qu'il voit.
      const yaw = scrollEased * Math.PI * 0.66;
      const pitch = -0.22 + scrollEased * 0.34;
      const dolly = -140 + scrollEased * 300;

      const cosY = Math.cos(yaw);
      const sinY = Math.sin(yaw);
      const cosP = Math.cos(pitch);
      const sinP = Math.sin(pitch);

      // La bande de balayage est définie à l'ÉCRAN, pas dans le monde.
      //
      // Elle balayait d'abord l'axe Y du monde : correct sur le papier, illisible
      // en pratique. La caméra tourne et avance en même temps, si bien que la
      // bande éclairée dérivait hors cadre dès la première section — vérifié en
      // capture, l'effet ne se lisait que dans le hero. Ancrée à l'écran, la
      // structure éclairée reste toujours devant le lecteur, et c'est la
      // rotation et l'avancée qui donnent le sentiment de traverser.
      const sweepScreenY = h * (0.30 + scrollEased * 0.42);
      const band = h * SWEEP_BAND;

      for (let i = 0; i < count; i++) {
        // Rotation Y puis X — projection perspective classique, écrite à la
        // main parce qu'elle tient en huit lignes.
        const x0 = wx[i]!;
        const y0 = wy[i]!;
        const z0 = wz[i]!;
        const x1 = x0 * cosY - z0 * sinY;
        const z1 = x0 * sinY + z0 * cosY;
        const y2 = y0 * cosP - z1 * sinP;
        const z2 = y0 * sinP + z1 * cosP + dolly;

        const d = FOV + z2;
        if (d <= 1) {
          // Derrière la caméra : hors champ, et surtout pas projeté — une
          // division par un dénominateur négatif retourne le point et produit
          // les traits fous qu'on voit dans les projections bâclées.
          scale[i] = 0;
          continue;
        }
        const s = FOV / d;
        px[i] = cx + x1 * s;
        py[i] = cy + y2 * s;
        scale[i] = s;

        const dist = Math.abs(py[i]! - sweepScreenY);
        lit[i] = dist < band ? 1 - dist / band : 0;
      }

      /* ── Segments. Un seul chemin par famille de couleur : changer de
            style de trait coûte, et les trier évite ce coût. ──────────── */
      ctx.lineWidth = 1;

      ctx.beginPath();
      for (let i = 0; i < count; i++) {
        if (scale[i]! === 0) continue;
        for (let j = i + 1; j < count; j++) {
          if (scale[j]! === 0) continue;
          if (lit[i]! === 0 && lit[j]! === 0) continue;
          const dx = px[i]! - px[j]!;
          const dy = py[i]! - py[j]!;
          if (dx * dx + dy * dy > LINK_DIST_SQ) continue;
          ctx.moveTo(px[i]!, py[i]!);
          ctx.lineTo(px[j]!, py[j]!);
        }
      }
      ctx.strokeStyle = `rgba(${ACID}, 0.11)`;
      ctx.stroke();

      /* ── Nœuds ────────────────────────────────────────────────────────
            Deux passes, gris puis acide, pour ne changer `fillStyle` que
            deux fois au lieu d'une fois par nœud. */
      ctx.beginPath();
      for (let i = 0; i < count; i++) {
        const s = scale[i]!;
        if (s === 0 || lit[i]! > 0) continue;
        const r = Math.max(0.4, s * 1.1);
        ctx.moveTo(px[i]! + r, py[i]!);
        ctx.arc(px[i]!, py[i]!, r, 0, Math.PI * 2);
      }
      ctx.fillStyle = `rgba(${GRID}, 0.30)`;
      ctx.fill();

      ctx.beginPath();
      for (let i = 0; i < count; i++) {
        const s = scale[i]!;
        if (s === 0 || lit[i]! === 0) continue;
        const r = Math.max(0.8, s * (1.4 + lit[i]! * 1.6));
        ctx.moveTo(px[i]! + r, py[i]!);
        ctx.arc(px[i]!, py[i]!, r, 0, Math.PI * 2);
      }
      ctx.fillStyle = `rgba(${ACID}, 0.55)`;
      ctx.fill();
    };

    // Mouvement réduit : une image, puis plus rien. La structure reste lisible,
    // le mouvement disparaît — c'est la demande, pas une animation ralentie.
    if (reduced) {
      draw();
      return () => ro.disconnect();
    }

    let raf = 0;
    let running = true;
    const io = new IntersectionObserver(([e]) => {
      running = e?.isIntersecting ?? false;
    });
    io.observe(canvas);

    const frame = (): void => {
      raf = requestAnimationFrame(frame);
      if (!running || document.hidden) return;
      readScroll();
      // Lissage exponentiel : le canvas décélère comme le reste de la page, au
      // lieu de coller image par image à la valeur brute du scroll.
      scrollEased += (scrollTarget - scrollEased) * 0.08;
      draw();
    };
    raf = requestAnimationFrame(frame);

    return () => {
      cancelAnimationFrame(raf);
      io.disconnect();
      ro.disconnect();
    };
  }, []);

  /* `z-0` et non `-z-10` : le fond opaque du body est peint par la racine du
     document, et tout indice négatif passerait DERRIÈRE lui — la canvas serait
     invisible. Elle se place donc juste au-dessus du fond, et le contenu est
     explicitement remonté au-dessus d'elle (voir (site)/layout.tsx). */
  return (
    <canvas
      ref={canvasRef}
      aria-hidden
      className="pointer-events-none fixed inset-0 z-0 h-full w-full"
    />
  );
}
