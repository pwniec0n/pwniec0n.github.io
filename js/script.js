const canvas = document.getElementById("rainbow-matrix");
const ctx = canvas.getContext("2d");

const encodedMessage =
  "V2FrZSB1cCwgcHduaWVzLi4uClRoZSB3b3JsZCBoYXMgeW91CmZvbGxvdyB0aGUgYmx1ZSBwd25pZS4KS25vY2ssIGtub2NrLCBwd25pZXMuIA==";

const message = encodedMessage.split("");

const fontSize = 15;

let columns = 0;
let drops = [];

function resizeCanvas() {
  canvas.width = window.innerWidth;
  canvas.height = window.innerHeight;

  columns = Math.floor(canvas.width / fontSize);

  /*
   * Preserve existing drop state when possible instead of resetting
   * the entire animation every time the browser is resized.
   */
  const oldDrops = drops;

  drops = Array.from(
    { length: columns },
    (_, i) => oldDrops[i] ?? Math.floor(Math.random() * canvas.height / fontSize)
  );
}

function draw() {
  ctx.fillStyle = "rgba(104, 78, 255, 0.3)";
  ctx.fillRect(
    0,
    0,
    canvas.width,
    canvas.height
  );

  ctx.fillStyle = "rgba(255, 123, 245, 0.7)";
  ctx.font = `${fontSize}px system-ui`;

  for (let i = 0; i < drops.length; i++) {
    const text =
      message[Math.floor(Math.random() * message.length)];

    ctx.fillText(
      text,
      i * fontSize,
      drops[i] * fontSize
    );

    if (
      drops[i] * fontSize > canvas.height &&
      Math.random() > 0.975
    ) {
      drops[i] = 0;
    }

    drops[i]++;
  }
}

resizeCanvas();

window.addEventListener(
  "resize",
  resizeCanvas
);

setInterval(
  draw,
  33
);

