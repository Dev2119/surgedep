import Footer from "../components/footer";
import Header from "../components/header";
import ContactPage from "./ContactPage";

export const metadata = {
  title: "Error Epson Printer Support",
};
export default function SuccessPage() {
  return (
    <div style={{ textAlign: "center", marginTop: "0px" }}>
         <Header />
      <ContactPage />
      <Footer />
    </div>
  );
}
