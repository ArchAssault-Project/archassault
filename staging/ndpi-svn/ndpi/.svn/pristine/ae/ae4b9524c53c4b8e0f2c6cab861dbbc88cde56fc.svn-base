lib_LTLIBRARIES = libndpi.la

noinst_HEADERS = ../include/ndpi_main.h \
		../include/ndpi_protocol_history.h \
		../include/ndpi_protocols.h \
		../include/ndpi_structs.h \
		../include/ndpi_utils.h \
		../include/linux_compat.h


# this will create a library 1.4.0
LIB_AC=1
LIB_REV=4
LIB_ANC=0

# ntop
AM_CFLAGS=-fPIC @PLATFORM_DEPENDENT@

libndpi_la_CPPFLAGS = -I$(top_srcdir)/src/include/  -I$(top_srcdir)/src/lib/third_party/include/
libndpi_la_LDFLAGS=-version-info ${LIB_AC}:${LIB_REV}:${LIB_ANC}

libndpi_la_SOURCES = \
			third_party/src/ahocorasick.c \
			third_party/src/node.c \
			third_party/src/sort.c \
			ndpi_main.c \
			protocols/afp.c \
			protocols/aimini.c \
			protocols/applejuice.c \
			protocols/armagetron.c \
			protocols/ayiya.c \
			protocols/battlefield.c \
			protocols/bgp.c \
			protocols/bittorrent.c \
			protocols/crossfire.c \
			protocols/dhcp.c \
			protocols/dhcpv6.c \
			protocols/directconnect.c \
			protocols/directdownloadlink.c \
			protocols/dns.c \
			protocols/dofus.c \
			protocols/edonkey.c \
			protocols/fasttrack.c \
			protocols/fiesta.c \
			protocols/filetopia.c \
			protocols/rtmp.c \
			protocols/florensia.c \
			protocols/ftp_control.c \
			protocols/ftp_data.c \
			protocols/gnutella.c \
			protocols/guildwars.c \
			protocols/halflife2_and_mods.c \
			protocols/http_activesync.c \
			protocols/http.c \
			protocols/iax.c \
			protocols/icecast.c \
			protocols/imesh.c \
			protocols/ipp.c \
			protocols/irc.c \
			protocols/jabber.c \
			protocols/kerberos.c \
			protocols/kontiki.c \
			protocols/ldap.c \
			protocols/mail_imap.c \
			protocols/mail_pop.c \
			protocols/mail_smtp.c \
			protocols/vmware.c \
			protocols/maplestory.c \
			protocols/mdns.c \
			protocols/meebo.c \
			protocols/mgcp.c \
			protocols/mms.c \
			protocols/msn.c \
			protocols/mssql.c \
			protocols/mysql.c \
			protocols/netbios.c \
			protocols/nfs.c \
			protocols/non_tcp_udp.c \
			protocols/tcp_udp.c \
			protocols/ntp.c \
			protocols/openft.c \
			protocols/oscar.c \
			protocols/pcanywhere.c \
			protocols/postgres.c \
			protocols/pplive.c \
			protocols/ppstream.c \
			protocols/pptp.c \
			protocols/qq.c \
			protocols/quake.c \
			protocols/rdp.c \
			protocols/rtp.c \
			protocols/rtsp.c \
			protocols/shoutcast.c \
			protocols/sip.c \
			protocols/smb.c \
			protocols/snmp.c \
			protocols/socrates.c \
			protocols/sopcast.c \
			protocols/soulseek.c \
			protocols/spotify.c \
			protocols/ssdp.c \
			protocols/ssh.c \
			protocols/ssl.c \
			protocols/stealthnet.c \
			protocols/steam.c \
			protocols/stun.c \
			protocols/syslog.c \
			protocols/tds.c \
			protocols/telnet.c \
			protocols/tftp.c \
			protocols/thunder.c \
			protocols/tvants.c \
			protocols/tvuplayer.c \
			protocols/usenet.c \
			protocols/veohtv.c \
			protocols/vnc.c \
			protocols/warcraft3.c \
			protocols/winmx.c \
			protocols/world_of_kung_fu.c \
			protocols/world_of_warcraft.c \
			protocols/xbox.c \
			protocols/xdmcp.c \
			protocols/yahoo.c \
			protocols/zattoo.c \
			protocols/dropbox.c \
			protocols/skype.c \
			protocols/citrix.c \
			protocols/dcerpc.c \
			protocols/netflow.c \
			protocols/sflow.c \
			protocols/radius.c \
			protocols/teamviewer.c \
			protocols/lotus_notes.c \
			protocols/gtp.c \
			protocols/h323.c \
			protocols/noe.c \
			protocols/ciscovpn.c \
			protocols/teamspeak.c \
			protocols/viber.c \
			protocols/openvpn.c \
			protocols/corba.c \
			protocols/oracle.c \
			protocols/rsync.c \
			protocols/rtcp.c \
			protocols/skinny.c \
			protocols/tor.c \
			protocols/whoisdas.c \
			protocols/collectd.c \
			protocols/socks5.c \
			protocols/socks4.c \
			protocols/pando.c

# NTOP protocols are at the end
