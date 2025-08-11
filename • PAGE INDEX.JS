import ProductList from "../components/Store/ProductList";
import SlotMachine from "../components/Games/SlotMachine";
import Chat from "../components/Chat/Chat";

export default function Home() {
  return (
    <div style={{ padding: 20 }}>
      <h1>منصة التجارة، التريدينغ، الألعاب والدردشة مع AI</h1>
      <ProductList />
      <SlotMachine />
      <Chat />
    </div>
  );
}