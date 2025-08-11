import { useState } from "react";

const symbols = ["🍒", "🍋", "🍉", "⭐", "7️⃣"];

export default function SlotMachine() {
  const [reels, setReels] = useState(["❓", "❓", "❓"]);
  const [result, setResult] = useState("");

  function spin() {
    const newReels = Array(3)
      .fill(0)
      .map(() => symbols[Math.floor(Math.random() * symbols.length)]);
    setReels(newReels);
    if (newReels.every((s) => s === newReels[0])) setResult("🎉 فزت!");
    else setResult("حاول مرة أخرى");
  }

  return (
    <div>
      <h3>لعبة السلوت ماشين</h3>
      <div style={{ fontSize: "3rem" }}>{reels.join(" ")}</div>
      <button onClick={spin}>إدور</button>
      <p>{result}</p>
    </div>
  );
}