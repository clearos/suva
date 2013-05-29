# Copyright 1999-2011 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Header: $

EAPI=3

DESCRIPTION="Suva/3 Client and Server"
HOMEPAGE="http://www.clearfoundation.com/"
#SRC_URI=""

LICENSE="GPL-2"
SLOT="0"
KEYWORDS="~amd64 ~x86"
#IUSE=""

DEPEND=">=dev-libs/openssl-0.9.6b"
RDEPEND="${DEPEND}"

inherit autotools subversion

ESVN_REPO_URI="svn://svn.pointclark.net/private/packages/internal/suva/branches/suva-triton"
ESVN_PROJECT="suva-snapshot"

src_prepare() {
	eautoreconf
}

src_configure() {
	econf
}

src_compile() {
	emake || die "emake failed"
}

src_install() {
	emake DESTDIR="${D}" install || die "emake install failed"
}
