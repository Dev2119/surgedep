import EpsonPrinter from "./epsonnet";

export const metadata = {
  title: "Epson Printer Support",
};


const page = () => {
  return (
      <EpsonPrinter />
  );
}

export default page;