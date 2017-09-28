#ifndef _SECURE_
#include <boost/regex.hpp>
#include <boost/algorithm/string/replace.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/algorithm/string/join.hpp>
#include <boost/algorithm/string.hpp>  
#include <iostream>
#include <iterator>
#include <algorithm>
#include <string>
extern "C" {
#include "entities.h"
}
# pragma warning(disable: 4996)

namespace antiFilter {
	int cpp_htoi(char *s);
	size_t _raw_url_decode(char *str, size_t len);
	std::string _urldecodespaces(const boost::smatch& match);
	std::string raw_url_decode(std::string &str);
	void remove_invisible_characters(std::string &str, bool url_encode);
	std::string remove_xss(std::string str);
	char *rand_str(char *str);
	std::string entity_decode(std::string str);
	std::string _decode_entity(const boost::smatch& match);
	void _do_never_allowed(std::string &str);
	void make_php_tag_safe(std::string &str);
	std::string _compact_exploded_words(const boost::smatch& match);
	std::string _filter_attributes(std::string &str);
	std::string _js_link_removal(const boost::smatch& match);
}
#endif // !_SECURE_
