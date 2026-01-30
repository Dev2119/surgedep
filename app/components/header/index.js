import Link from "next/link";
import ButtonLink from "../ButtonLink";
import Image from "next/image";
const Header = () => {
    return (
       <>
      <header style={{ backgroundColor: "#d4eeff" }}>
  <nav aria-label="Global" className="mx-auto flex max-w-7xl items-center justify-between p-6 lg:px-8">
    <div className="flex lg:flex-1">
    
        <Image
      src="/images/l.jpg"
      alt="Printers with blue schematic background"
      width={99}
      height={24}
    />
      
    </div>
    <div className="flex lg:hidden">
      <div type="button" command="show-modal" commandfor="mobile-menu" className="-m-2.5 inline-flex items-center justify-center rounded-md p-2.5 text-gray-700">
        <Link href="/contact-us" className="text-2xl/6 font-semibold text-gray-900 uppercase buttonStyle">  
        Contact Us
    </Link>
      </div>
    </div>
    <el-popover-group className="hidden lg:flex lg:gap-x-12">
      <Link href="#" className="text-2xl/6 font-semibold text-gray-900 uppercase">Officejet</Link>
      <Link href="#" className="text-2xl/6 font-semibold text-gray-900 uppercase">Laserjet</Link>
      <Link href="#" className="text-2xl/6 font-semibold text-gray-900 uppercase">Pixma</Link>
      <Link href="#" className="text-2xl/6 font-semibold text-gray-900 uppercase">Maxify</Link>
      <Link href="#" className="text-2xl/6 font-semibold text-gray-900 uppercase">XP Series</Link>
    </el-popover-group>
    <div className="hidden lg:flex lg:flex-1 lg:justify-end">
      <Link href="/contact-us" className="text-2xl/6 font-semibold text-gray-900 uppercase buttonStyle">  
        Contact Us
    </Link>
    </div>
  </nav>

</header>
       </>
    );
}

export default Header;
