# Copyright 1999-2016 Gentoo Foundation
# Distributed under the terms of the GNU General Public License v2
# $Id$

EAPI=5

DESCRIPTION="mndc"
HOMEPAGE="https://github.com/RealKelsar/mndc"
#SRC_URI=""

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="-*"
IUSE=""

DEPEND="
	>=dev-qt/qtcore-5.4.2
	>=dev-qt/qtwidgets-5.4.2
	>=dev-qt/qtnetwork-5.4.2
	"
RDEPEND="${DEPEND}
	>=net-analyzer/traceroute-2.0.20
	>=net-misc/iputils-20121221-r1
	>=net-dns/bind-tools-9.10.3_p2
	>=net-analyzer/nmap-7.01
	>=net-misc/whois-5.1.5
	>=net-misc/openssh-7.1_p1-r2
	>=app-admin/sudo-1.8.15-r1
"

inherit git-r3
inherit cmake-utils

EGIT_REPO_URI="https://github.com/RealKelsar/mndc"

