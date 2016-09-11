# Maintainer: Michal Krenek (Mikos) <m.krenek@gmail.com>
pkgname=pyxolotl
pkgver=0.2
pkgrel=1
pkgdesc="Send and receive messages encrypted with Axolotl (Double Ratchet) protocol"
arch=('any')
url="https://github.com/xmikos/pyxolotl"
license=('GPL3')
depends=('python-axolotl')
makedepends=('python-setuptools')
source=(https://github.com/xmikos/pyxolotl/archive/v$pkgver.tar.gz)

build() {
  cd "$srcdir/$pkgname-$pkgver"
  python setup.py build
}

package() {
  cd "$srcdir/$pkgname-$pkgver"
  python setup.py install --root="$pkgdir"
}

# vim:set ts=2 sw=2 et:
