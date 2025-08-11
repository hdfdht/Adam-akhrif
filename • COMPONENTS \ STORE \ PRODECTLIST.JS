import { useState, useEffect } from "react";

export default function ProductList() {
  const [products, setProducts] = useState([]);

  useEffect(() => {
    fetch("/api/products")
      .then((res) => res.json())
      .then(setProducts);
  }, []);

  return (
    <div>
      <h2>منتجاتنا</h2>
      <ul>
        {products.map((p) => (
          <li key={p.id}>
            {p.name} - {p.price} درهم
          </li>
        ))}
      </ul>
    </div>
  );
}