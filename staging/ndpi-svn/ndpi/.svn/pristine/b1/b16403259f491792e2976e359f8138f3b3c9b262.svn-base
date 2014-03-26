/*
 * ndpi_content_match.c
 *
 * Copyright (C) 2011-14 - ntop.org
 *
 * This file is part of nDPI, an open source deep packet inspection
 * library based on the OpenDPI and PACE technology by ipoque GmbH
 *
 * nDPI is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * nDPI is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with nDPI.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

typedef struct {
  char *string_to_match, *proto_name;
  int protocol_id;
} ndpi_protocol_match;

/* ****************************************************** */

/*
  Host-based match
  
  HTTP:  Server: field
  HTTPS: Server certificate name  
 */

ndpi_protocol_match host_match[] = {
  { "amazon.com",			"Amazon",		NDPI_SERVICE_AMAZON },
  { "amazonaws.com",			"Amazon",		NDPI_SERVICE_AMAZON },
  { "amazon-adsystem.com",		"Amazon",		NDPI_SERVICE_AMAZON },
  { ".apple.com",			"Apple",		NDPI_SERVICE_APPLE },
  { ".mzstatic.com",			"Apple",		NDPI_SERVICE_APPLE },
  { ".icloud.com",			"AppleiCloud",		NDPI_SERVICE_APPLE_ICLOUD },
  { "itunes.apple.com",			"AppleiTunes",		NDPI_SERVICE_APPLE_ITUNES },
  { ".cnn.c",				"CNN",			NDPI_SERVICE_CNN },
  { ".cnn.net",				"CNN",			NDPI_SERVICE_CNN },
  { ".dropbox.com",			"DropBox",		NDPI_SERVICE_DROPBOX },
  { ".ebay.com",			"eBay",			NDPI_SERVICE_EBAY },
  { ".ebaystatic.com",			"eBay",			NDPI_SERVICE_EBAY },
  { ".ebaydesc.com",			"eBay",			NDPI_SERVICE_EBAY },
  { ".ebayrtm.com",			"eBay",			NDPI_SERVICE_EBAY },
  { ".facebook.com",			"Facebook",		NDPI_SERVICE_FACEBOOK },
  { ".fbcdn.net",			"Facebook",		NDPI_SERVICE_FACEBOOK },
  { "fbcdn-",				"Facebook",		NDPI_SERVICE_FACEBOOK },  /* fbcdn-video-a-akamaihd.net */
  { ".gstatic.com",			"Google",		NDPI_SERVICE_GOOGLE },
  { ".googlesyndication.com",		"Google",		NDPI_SERVICE_GOOGLE },
  { ".googletagservices.com",		"Google",		NDPI_SERVICE_GOOGLE },
  { ".2mdn.net",			"Google",		NDPI_SERVICE_GOOGLE },
  { ".doubleclick.net",			"Google",		NDPI_SERVICE_GOOGLE }, /* Ads */
  { "googleads.",			"Google",		NDPI_SERVICE_GOOGLE },
  { "google-analytics.",		"Google",		NDPI_SERVICE_GOOGLE },
  { "googleusercontent.",		"Google",		NDPI_SERVICE_GOOGLE },
  { "googleadservices.",		"Google",		NDPI_SERVICE_GOOGLE },
  { "maps.google.",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS },
  { "maps.gstatic.com",			"GoogleMaps",		NDPI_SERVICE_GOOGLE_MAPS },
  { ".gmail.",				"GMail",		NDPI_SERVICE_GMAIL },
  { "mail.google.",			"GMail",		NDPI_SERVICE_GMAIL },
  { ".grooveshark.com",			"GrooveShark",		NDPI_SERVICE_GROOVESHARK },
  { ".last.fm",				"LastFM",		NDPI_SERVICE_LASTFM },
  { "msn.com",				"MSN",			NDPI_SERVICE_MSN },
  { ".netflix.com",			"NetFlix",		NDPI_SERVICE_NETFLIX },
  { ".skype.com",			"Skype",		NDPI_SERVICE_SKYPE },
  { ".skypeassets.com",			"Skype",		NDPI_SERVICE_SKYPE },
  { ".tuenti.com",			"Tuenti",		NDPI_SERVICE_TUENTI },
  { ".twttr.com",			"Twitter",		NDPI_SERVICE_TWITTER },
  { "twitter.",				"Twitter",		NDPI_SERVICE_TWITTER },
  { "twimg.com",			"Twitter",		NDPI_SERVICE_TWITTER },
  { ".viber.com",			"Viber",		NDPI_SERVICE_VIBER },
  { "wikipedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA },
  { "wikimedia.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA },
  { "mediawiki.",			"Wikipedia",		NDPI_SERVICE_WIKIPEDIA },
  { "wikimediafoundation.",		"Wikipedia",		NDPI_SERVICE_WIKIPEDIA },
  { ".whatsapp.net",			"WhatsApp",		NDPI_SERVICE_WHATSAPP },
  { ".yahoo.",				"Yahoo",		NDPI_SERVICE_YAHOO },
  { "yimg.com",				"Yahoo",		NDPI_SERVICE_YAHOO },
  { "yahooapis.",			"Yahoo",		NDPI_SERVICE_YAHOO },
  { "youtube.",				"YouTube",		NDPI_SERVICE_YOUTUBE },
  { ".googlevideo.com",			"YouTube",		NDPI_SERVICE_YOUTUBE },
  { ".ytimg.com",			"YouTube",		NDPI_SERVICE_YOUTUBE },
  { "youtube-nocookie.",		"YouTube",		NDPI_SERVICE_YOUTUBE },
  { ".google.",				"Google",		NDPI_SERVICE_GOOGLE },
  { NULL, 0 }
};


/*
  Mime-type content match match  
*/
ndpi_protocol_match content_match[] = {
  { "audio/mpeg",			NULL,		        NDPI_CONTENT_MPEG },
  { "audio/x-mpeg",			NULL,		        NDPI_CONTENT_MPEG },
  { "audio/mpeg3",			NULL,		        NDPI_CONTENT_MPEG },
  { "audio/mp4a",			NULL,		        NDPI_CONTENT_MPEG },
  { "video/mpeg",			NULL,		        NDPI_CONTENT_MPEG },
  { "video/nsv",			NULL,		        NDPI_CONTENT_MPEG },
  { "misc/ultravox",			NULL,		        NDPI_CONTENT_MPEG },
  { "audio/ogg",			NULL,		        NDPI_CONTENT_OGG },
  { "video/ogg",			NULL,		        NDPI_CONTENT_OGG },
  { "application/ogg",			NULL,		        NDPI_CONTENT_OGG },
  { "video/flv",			NULL,		        NDPI_CONTENT_FLASH },
  { "video/x-flv",			NULL,		        NDPI_CONTENT_FLASH },
  { "application/x-fcs",		NULL,		        NDPI_CONTENT_FLASH },
  { "application/x-shockwave-flash",	NULL,		        NDPI_CONTENT_FLASH },
  { "video/flash",			NULL,		        NDPI_CONTENT_FLASH },
  { "application/flv",			NULL,		        NDPI_CONTENT_FLASH },
  { "flv-application/octet-stream",	NULL,		        NDPI_CONTENT_FLASH },
  { "application/futuresplash",		NULL,		        NDPI_CONTENT_FLASH },
  { "video/quicktime",			NULL,		        NDPI_CONTENT_QUICKTIME },
  { "video/mp4",			NULL,		        NDPI_CONTENT_QUICKTIME },
  { "video/x-m4v",			NULL,		        NDPI_CONTENT_QUICKTIME },
  { "audio/x-pn-realaudio",		NULL,		        NDPI_CONTENT_REALMEDIA },
  { "application/vnd.rn-realmedia",	NULL,		        NDPI_CONTENT_REALMEDIA },
  { "video/x-ms-",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "asf",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "asx",			        NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "video/x-msvideo",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "audio/x-wav",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "application/vnd.ms.wms-hdr.asfv1",	NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "NSPlayer/",			NULL,		        NDPI_CONTENT_WINDOWSMEDIA },
  { "application/x-mms-framed",		NULL,		        NDPI_CONTENT_MMS },
  { "Xbox Live Client/",		NULL,		        NDPI_PROTOCOL_XBOX },
  { "Windows-Update-Agent",		NULL,		        NDPI_PROTOCOL_WINDOWS_UPDATE },
  { "audio/webm",			NULL,		        NDPI_CONTENT_WEBM },
  { "video/webm",			NULL,		        NDPI_CONTENT_WEBM },
  { "application/x-rtsp-tunnelled",	NULL,		        NDPI_PROTOCOL_RTSP },
  { NULL, 0 }
};
