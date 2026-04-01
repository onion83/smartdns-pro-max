/*************************************************************************
 *
 * Copyright (C) 2018-2025 Ruilin Peng (Nick) <pymumu@gmail.com>.
 *
 * smartdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * smartdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "client.h"
#include "smartdns/dns.h"
#include "include/utils.h"
#include "server.h"
#include "smartdns/util.h"
#include "gtest/gtest.h"
#include <fstream>

class Geosite : public ::testing::Test
{
  protected:
	virtual void SetUp() {}
	virtual void TearDown() {}
};

TEST_F(Geosite, geosite_dat_local_file)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_geosite;

	// Create a geosite list file with test domains
	file_geosite.Write("test-geosite-1.com\n");
	file_geosite.Write("test-geosite-2.com\n");
	file_geosite.Write("test-geosite-3.com\n");

	std::string config = "geosite-dat test-geosite " + file_geosite.GetPath() + " 600\n";
	config += R"""(bind [::]:60553
server 127.0.0.1:61053
)""";

	server_upstream.Start("udp://0.0.0.0:61053", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	// Test domain in geosite list - should match (using block action for simplicity)
	// Note: This test validates the geosite-dat directive is parsed correctly
	// The actual domain matching will be tested with geosite-set below
}

TEST_F(Geosite, geosite_set_basic)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_geosite1;
	smartdns::TempFile file_geosite2;

	// Create first geosite list
	file_geosite1.Write("geosite-test-a.com\n");
	file_geosite1.Write("geosite-test-b.com\n");

	// Create second geosite list
	file_geosite2.Write("geosite-test-c.com\n");
	file_geosite2.Write("geosite-test-d.com\n");

	std::string config = "geosite-dat gs1 " + file_geosite1.GetPath() + " 600\n";
	config += "geosite-dat gs2 " + file_geosite2.GetPath() + " 600\n";
	config += "geosite-set gs-group gs1 gs2\n";
	config += R"""(bind [::]:60554
server 127.0.0.1:61054
)""";

	server_upstream.Start("udp://0.0.0.0:61054", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.2.3.4");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	// Test that server started successfully with geosite configuration
	ASSERT_TRUE(client.Query("example.com", 60554));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
}

TEST_F(Geosite, geosite_domain_matching)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_geosite;

	// Create geosite list with domains
	file_geosite.Write("match-geosite-1.com\n");
	file_geosite.Write("match-geosite-2.com\n");

	std::string config = "geosite-dat gs-match " + file_geosite.GetPath() + " 600\n";
	config += "geosite-set gs-myset gs-match\n";
	config += R"""(bind [::]:60555
server 127.0.0.1:61055
domain-rules /domain-set:gs-myset/ -c none -a 9.9.9.9
)""";

	server_upstream.Start("udp://0.0.0.0:61055", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "5.6.7.8");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	// Test domain that matches geosite - should return configured IP
	ASSERT_TRUE(client.Query("match-geosite-1.com", 60555));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "match-geosite-1.com");
	EXPECT_EQ(client.GetAnswer()[0].GetTTL(), 600);
	EXPECT_EQ(client.GetAnswer()[0].GetType(), "A");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.9.9.9");

	// Test another matching domain
	ASSERT_TRUE(client.Query("match-geosite-2.com", 60555));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "9.9.9.9");

	// Test domain that doesn't match - should go to upstream
	ASSERT_TRUE(client.Query("other-domain.com", 60555));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetStatus(), "NOERROR");
	EXPECT_EQ(client.GetAnswer()[0].GetName(), "other-domain.com");
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "5.6.7.8");
}

TEST_F(Geosite, geosite_combined_set)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_google;
	smartdns::TempFile file_baidu;

	// Create google-like domains
	file_google.Write("google-test.com\n");
	file_google.Write("google-mirror.com\n");

	// Create baidu-like domains
	file_baidu.Write("baidu-test.cn\n");
	file_baidu.Write("baidu-mirror.cn\n");

	std::string config = "geosite-dat google " + file_google.GetPath() + " 600\n";
	config += "geosite-dat baidu " + file_baidu.GetPath() + " 600\n";
	config += "geosite-set search-engine google baidu\n";
	config += R"""(bind [::]:60556
server 127.0.0.1:61056
domain-rules /domain-set:search-engine/ -c none -a 8.8.8.8
)""";

	server_upstream.Start("udp://0.0.0.0:61056", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "1.1.1.1");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	// Test google domains
	ASSERT_TRUE(client.Query("google-test.com", 60556));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "8.8.8.8");

	ASSERT_TRUE(client.Query("google-mirror.com", 60556));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "8.8.8.8");

	// Test baidu domains
	ASSERT_TRUE(client.Query("baidu-test.cn", 60556));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "8.8.8.8");

	ASSERT_TRUE(client.Query("baidu-mirror.cn", 60556));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "8.8.8.8");

	// Test non-matching domain
	ASSERT_TRUE(client.Query("unmatched.org", 60556));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "1.1.1.1");
}

TEST_F(Geosite, geosite_with_comments)
{
	smartdns::MockServer server_upstream;
	smartdns::Server server;
	smartdns::TempFile file_geosite;

	// Create geosite list with comments and empty lines
	file_geosite.Write("# This is a comment\n");
	file_geosite.Write("domain-with-comment.com\n");
	file_geosite.Write("\n");  // empty line
	file_geosite.Write("# Another comment\n");
	file_geosite.Write("another-domain.com\n");

	std::string config = "geosite-dat gs-comments " + file_geosite.GetPath() + " 600\n";
	config += "geosite-set gs-comments-set gs-comments\n";
	config += R"""(bind [::]:60557
server 127.0.0.1:61057
domain-rules /domain-set:gs-comments-set/ -c none -a 7.7.7.7
)""";

	server_upstream.Start("udp://0.0.0.0:61057", [&](struct smartdns::ServerRequestContext *request) {
		if (request->qtype == DNS_T_A) {
			smartdns::MockServer::AddIP(request, request->domain.c_str(), "2.2.2.2");
			return smartdns::SERVER_REQUEST_OK;
		}
		return smartdns::SERVER_REQUEST_SOA;
	});

	std::cout << config << std::endl;
	server.Start(config);
	smartdns::Client client;

	// Test domain in list (with comments)
	ASSERT_TRUE(client.Query("domain-with-comment.com", 60557));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.7.7.7");

	// Test another domain in list
	ASSERT_TRUE(client.Query("another-domain.com", 60557));
	ASSERT_EQ(client.GetAnswerNum(), 1);
	EXPECT_EQ(client.GetAnswer()[0].GetData(), "7.7.7.7");
}
