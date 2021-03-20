pkgname=wsl_issue_4898
pkgver=0.0.1
pkgrel=1
pkgdesc="aaaa"
arch=('x86_64' 'i686' 'arm' 'armv6h' 'armv7h' 'aarch64')
license=('Unlicense')
depends=('glibc')
#makedepends=('gcc')
source=(
	"wsl_issue_4898.c"
)
sha256sums=('SKIP')
install="${pkgname}.install"

build() {
	cd "${srcdir}"
	gcc -shared -fPIC -o libwsl_issue_4898.so wsl_issue_4898.c
}

package() {
	cd "${srcdir}"

	install -D -m755 libwsl_issue_4898.so "${pkgdir}/usr/lib/libwsl_issue_4898.so"
}
