export default function handler(req, res) {
  // 20 منتوج مثالياً، يمكن تزيد أو تبدل
  const products = [
    { id: 1, name: "منتوج 1", price: 100 },
    { id: 2, name: "منتوج 2", price: 250 },
    // ... زيد حتى 20
  ];
  res.status(200).json(products);
}