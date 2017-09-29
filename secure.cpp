#include "secure.h"

namespace antiFilter { 

		int cpp_htoi(char *s) {
			int value;
			int c;

			//转为无符号字节
			c = ((unsigned char *)(s))[0];
			if (isupper(c)) {
				c = tolower(c);
			}
			value = (c >= '0'&&c <= '9' ? c - '0' : c - 'a' + 10) * 16;

			c = ((unsigned char *)(s))[1];
			if (isupper(c)) {
				c = tolower(c);
			}
			value += c >= '0'&&c <= '9' ? c - '0' : c - 'a' + 10;

			return (value);
		}

		size_t _raw_url_decode(char *str, size_t len)
		{
			char *dest = str;
			char *data = str;

			while (len--) {
				if (*data == '%'&&len >= 2 && isxdigit((int)*(data + 1)) && isxdigit((int)*(data + 2))) {
					*dest = (char)antiFilter::cpp_htoi(data + 1);
					data += 2;
					len -= 2;
				}
				else {
					*dest = *data;
				}
				data++;
				dest++;
			}
			*dest = '\0';

			return dest - str;
		}



		std::string _urldecodespaces(const boost::smatch& match) {
			std::string input(match[0]);
			//std::reverse(out.begin(), out.end());
			//std::cout << input << "\n";
			boost::regex expression("\\s+");

			std::string nospaces=regex_replace(input,expression,"",boost::match_perl);
			return (nospaces == input) ? input : antiFilter::raw_url_decode(nospaces);
		}

		std::string raw_url_decode(std::string &str) {
			char * pstr = new char[str.length() + 1];
			strcpy(pstr, str.c_str());
			_raw_url_decode(pstr, strlen(pstr));
			str = pstr;
			//free
			delete pstr;
			return str;
		}
		
		/*移除不可见字符
		*/
		void remove_invisible_characters(std::string &str,bool url_encode=true) {
			std::vector<char *> non_displayables;
			if (url_encode) {
				non_displayables.insert(non_displayables.end(), "%0[0-8bcef]");
				non_displayables.insert(non_displayables.end(), "%1[0-9a-f]");
				non_displayables.insert(non_displayables.end(), "%7f");
			}
			non_displayables.insert(non_displayables.end(), "[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]+");
			boost::regex expression;
			for (auto non_displayable = non_displayables.begin(); non_displayable != non_displayables.end();++non_displayable) {
				expression.assign(*non_displayable, boost::regex::icase);
				str = boost::regex_replace(str, expression, "", boost::match_perl);
			}
		}

		std::string _convert_attribute(const boost::smatch& match) {
			std::string input(match[0]);
			boost::algorithm::replace_all(input, ">", "&gt;");
			boost::algorithm::replace_all(input, "<", "&lt;");
			boost::algorithm::replace_all(input, "\\", "\\\\");
			return input;
		}

		char *rand_str(char *str)
		{
			int len = 17;
			static const char alphanum[] =
				"0123456789"
				"abcdefghijklmnopqrstuvwxyz";
			for (int i = 0; i < len-1; ++i) {
				str[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
			}
			str[len-1] = 0;
			return str;
		}

		std::string entity_decode(std::string str) {
			if (str.find_first_of("&") == std::string::npos) {
				return str;
			}
			std::string str_compare;
			boost::regex expression("&[a-z]{2,}(?![a-z;])", boost::regex::icase);
			boost::regex expression2("(&#(?:x0*[0-9a-f]{2,5}(?![0-9a-f;])|(?:0*\\d{2,4}(?![0-9;]))))", boost::regex::icase);

			std::map<std::string, std::string> replace;
			do {
				replace.clear();
				str_compare=str;
				//preg_match_all
				boost::sregex_token_iterator iter(str.begin(), str.end(), expression, 0);
				boost::sregex_token_iterator end; 

				for (; iter != end; ++iter) {
					std::map<std::string, std::string>::iterator map_it;
					for (map_it=html_entities_map.begin();map_it!=html_entities_map.end();++map_it){
						std::string data = iter->str();
						std::transform(data.begin(), data.end(), data.begin(), ::tolower);
						if (map_it->second == data + ";") {
							replace[data] = map_it->first;
						}
					}
				}
				for (std::map<std::string, std::string>::iterator re_it = replace.begin(); re_it != replace.end(); ++re_it) {
					boost::algorithm::replace_all(str,re_it->first,re_it->second);
				}
				str = boost::regex_replace(str, expression2, "$1;");
				//5.4以下使用
				/*for (std::map<std::string, std::string>::iterator entity_it = html_entities_map.begin(); entity_it != html_entities_map.end(); ++entity_it) {
					boost::algorithm::replace_all(str, entity_it->second, entity_it->first);
				}*/
				char * pstr = new char[str.length() + 1];
				strcpy(pstr, str.c_str());
				decode_html_entities_utf8(pstr, 0);
				str = pstr;
				//free
				delete pstr;

			} while (str_compare != str);
			return str;
		}

		std::string _decode_entity(const boost::smatch& match) {
			static std::string hash;
			if (hash.size() == 0) {
				char* _hash = new char[17];
				rand_str(_hash);
				hash = _hash;
				delete _hash;
			}
			std::string input(match[0]);
			boost::regex expression("\\&([a-z\\_0-9\\-]+)=([a-z\\_0-9\\-/]+)", boost::regex::icase);
			std::string replace = hash + "$1=$2";
			input = boost::regex_replace(input, expression, replace);
			input = entity_decode(input);
			boost::algorithm::replace_all(input, hash, "&");
			return input;
		}

		void _do_never_allowed(std::string &str) {
			for (std::map<std::string, std::string>::iterator it=_never_allowed_str.begin(); it != _never_allowed_str.end(); ++it) {
				boost::algorithm::replace_all(str, it->first, it->second);
			}
			int i = 0;
			boost::regex expression;
			for (i = 0; i < _never_allowed_regex.size(); ++i) {
				expression.assign(_never_allowed_regex[i], boost::regex::icase);
				str = boost::regex_replace(str, expression, "[removed]");
			}
		}

		void make_php_tag_safe(std::string &str) {
			boost::algorithm::replace_all(str, "<?", "&lt;?");
			boost::algorithm::replace_all(str, "?>", "?&gt;");
		}

		std::string _compact_exploded_words(const boost::smatch& match) {
			std::string m1(match[1]);
			std::string m2(match[2]);
			boost::regex expression("\\s+");
			return boost::regex_replace(m1, expression, "")+ m2;
		}

		std::string _filter_attributes(std::string &str) {
			boost::regex expression;
			expression.assign("\\s*[a-z\\-]+\\s*=\\s*(\042|\047)([^\042|\047]*?)(\042|\047)", boost::regex::icase);
			boost::sregex_token_iterator iter(str.begin(), str.end(), expression, 0);
			boost::sregex_token_iterator end;
			expression.assign("\\*.*?\\*");
			std::string out;
			for (; iter != end; ++iter) {
				//std::cout << iter->str() << "\n";
				out+=boost::regex_replace(iter->str(), expression, "");
			}
			return out;
		}

		std::string _js_link_removal(const boost::smatch& match) {
			std::string m0(match[0]);
			std::string m1(match[1]);
			std::string filter_m1;
			boost::regex expression("href=.*?(?:(?:alert|prompt|confirm)(?:\\(|&#40;)|javascript:|livescript:|mocha:|charset=|window\\.|document\\.|\\.cookie|<script|<xss|d\\s*a\\s*t\\s*a\\s*:)",boost::regex::icase);
			filter_m1 = _filter_attributes(m1);
			filter_m1=boost::regex_replace(filter_m1, expression, "");
			boost::algorithm::replace_all(m0, m1, filter_m1);
			return m0;
		}

		std::string _js_img_removal(const boost::smatch& match) {
			std::string m0(match[0]);
			std::string m1(match[1]);
			std::string filter_m1;
			boost::regex expression("src=.*?(?:(?:alert|prompt|confirm|eval)(?:\\(|&#40;)|javascript:|livescript:|mocha:|charset=|window\\.|document\\.|\\.cookie|<script|<xss|base64\\s*,)", boost::regex::icase);
			filter_m1 = _filter_attributes(m1);
			filter_m1 = boost::regex_replace(filter_m1, expression, "");
			boost::algorithm::replace_all(m0, m1, filter_m1);
			return m0;
		}

		std::string _sanitize_naughty_html(const boost::smatch& match) {
			std::string m0(match[0]);
			std::string m1(match[1]);
			std::string m2(match[2]);
			std::string m4(match[4]);
			std::string m5(match[5]);
			std::string m6(match[6]);
			std::string tmp;
			std::locale loc;
			boost::regex attributes_pattern;
			boost::regex is_evil_pattern;
			boost::regex expression("^[^a-z]+", boost::regex::icase);
			boost::match_results<std::string::const_iterator> attribute;
			std::string name;
			std::string value;
			std::string trim_value;
			std::string new_attributes("");
			boost::smatch results;
			std::vector<std::string> attributes;

			/*expression.assign("(?<name>[^\\s\042\047>/=]+)(?:\\s*=(?<value>[^\\s\042\047=><`]+|\\s*\042[^\042]*\042|\\s*\047[^\047]*\047|\\s*(?:[^\\s\042\047=><`]*)))", boost::regex::icase);
			boost::match_results<std::string::const_iterator> what;
			boost::match_flag_type flags = boost::match_default;
			std::string::const_iterator s = str.begin();
			std::string::const_iterator e = str.end();
			while (boost::regex_search(s, e, what, expression, flags)) {
				std::cout << what.position() << std::endl;
				std::string in(what[0]);
				std::string on(what[1]);
				std::string::difference_type l = what.length();
				std::string::difference_type p = what.position();
				s += p + l;
			}*/
			//slash match[2]
			//tagName match[4]
			//attributes match[5]
			//closeTag match[6]
			std::string low_m4 = m4;
			std::transform(low_m4.begin(), low_m4.end(), low_m4.begin(), ::tolower);
			if (m6.size() == 0) {
				return "&lt;" + m1;
			}
			else if (std::find(naughty_tags.begin(), naughty_tags.end(), low_m4) != naughty_tags.end()) {
				return "&lt;"+m1+"&gt;";
			}
			else if (match.size()>=5) {
				//name attribute[1]
				//value attribute[2]
				attributes_pattern.assign("(?<name>[^\\s\042\047>/=]+)(?:\\s*=(?<value>[^\\s\042\047=><`]+|\\s*\042[^\042]*\042|\\s*\047[^\047]*\047|\\s*(?:[^\\s\042\047=><`]*)))",boost::regex::icase);	
				is_evil_pattern.assign("^("+boost::algorithm::join(evil_attributes, std::string("|"))+")$",boost::regex::icase);
				std::string::const_iterator s;
				std::string::const_iterator e;
				do {
					m5 = boost::regex_replace(m5, expression, "", boost::match_perl);

					s = m5.begin();
					e = m5.end();
					if (!boost::regex_search(s, e, attribute, attributes_pattern)) {
						break;
					}

					name.assign(attribute[1]);
					value.assign(attribute[2]);
					trim_value = value;
					boost::trim(trim_value);
					if (boost::regex_search(name, results, is_evil_pattern)|| trim_value =="") {
						attributes.push_back("xss=removed");
					}
					else {
						attributes.push_back(attribute[0]);
					}

					std::string::difference_type l = attribute.length();
					std::string::difference_type p = attribute.position();
					s += p + l;
				} while (s != e);

				if (attributes.size() != 0) {
					new_attributes = " " + boost::algorithm::join(attributes, std::string(" "));
				}

				return "<" + m2 + m4 + new_attributes + ">";
			}

			

			return m0;
		}

		std::string remove_xss(std::string str) {
			remove_invisible_characters(str, true);
			boost::regex expression;
			if (str.find_first_of("%") != std::string::npos) {
				std::string oldstr;
				expression.assign("%(?:\\s*[0-9a-f]){2,}", boost::regex::icase);
				do {
					oldstr = str;
					str = raw_url_decode(str);
					str = boost::regex_replace(str, expression, antiFilter::_urldecodespaces, boost::match_perl);
				} while (oldstr != str);
			}
			expression.assign("[^a-z0-9>]+[a-z0-9]+=[\'\"].*?[\'\"]", boost::regex::icase);
			str=boost::regex_replace(str,expression,antiFilter::_convert_attribute,boost::match_perl);
			expression.assign("<\\w+.*", boost::regex::icase);
			str = boost::regex_replace(str, expression, antiFilter::_decode_entity, boost::match_perl);
			remove_invisible_characters(str, true);
			boost::algorithm::replace_all(str, "\t", " ");
			_do_never_allowed(str);
			make_php_tag_safe(str);
			int i = 0;
			for (i = 0; i < words.size(); ++i) {
				expression.assign(words[i], boost::regex::icase);
				str = boost::regex_replace(str, expression, antiFilter::_compact_exploded_words, boost::match_perl);
			}
			std::string original;
			boost::smatch results;


			do {
				original = str;
				expression.assign("<a", boost::regex::icase);
				if (boost::regex_search(str, results, expression)) {
					expression.assign("<a(?:rea)?[^a-z0-9>]+([^>]*?)(?:>|$)", boost::regex::icase);
					str = boost::regex_replace(str, expression, antiFilter::_js_link_removal, boost::match_perl);
				}

				expression.assign("<img", boost::regex::icase);
				if (boost::regex_search(str, results, expression)) {
					expression.assign("<img[^a-z0-9]+([^>]*?)(?:\\s?/?>|$)", boost::regex::icase);
					str = boost::regex_replace(str, expression, antiFilter::_js_img_removal, boost::match_perl);
				}

				expression.assign("script|xss", boost::regex::icase);
				if (boost::regex_search(str, results, expression)) {
					expression.assign("</*(?:script|xss).*?>", boost::regex::icase);
					str = boost::regex_replace(str, expression, "[removed]", boost::match_perl);
				}


			} while (original != str);
			/*
			.'<((?<slash>/*\s*)((?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)|.+)' // tag start and name, followed by a non-tag character
			.'[^\s\042\047a-z0-9>/=]*' // a valid attribute character immediately after the tag would count as a separator
			// optional attributes
			.'(?<attributes>(?:[\s\042\047/=]*' // non-attribute characters, excluding > (tag close) for obvious reasons
			.'[^\s\042\047>/=]+' // attribute characters
			// optional attribute-value
				.'(?:\s*=' // attribute-value separator
					.'(?:[^\s\042\047=><`]+|\s*\042[^\042]*\042|\s*\047[^\047]*\047|\s*(?U:[^\s\042\047=><`]*))' // single, double or non-quoted value
				.')?' // end optional attribute-value group
			.')*)' // end optional attributes group
			.'[^>]*)(?<closeTag>\>)?
			*/
			//slash match[2]
			//tagName match[4]
			//attributes match[5]
			//closeTag match[6]
			expression.assign("<((?<slash>/*\\s*)((?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)|.+)[^\\s\042\047a-z0-9>/=]*(?<attributes>(?:[\\s\042\047/=]*[^\\s\042\047>/=]+(?:\\s*=(?:[^\\s\042\047=><`]+|\\s*\042[^\042]*\042|\\s*\047[^\047]*\047|\\s*(?:[^\\s\042\047=><`]*)))?)*)[^>]*)(?<closeTag>>)?",boost::regex::icase);

			do {
				original = str;
				str = boost::regex_replace(str, expression, antiFilter::_sanitize_naughty_html, boost::match_perl);
			} while (original != str);


			/*
			* Sanitize naughty scripting elements
			*
			* Similar to above, only instead of looking for
			* tags it looks for PHP and JavaScript commands
			* that are disallowed. Rather than removing the
			* code, it simply converts the parenthesis to entities
			* rendering the code un-executable.
			*
			* For example:	eval('some code')
			* Becomes:	eval&#40;'some code'&#41;
			*/
			expression.assign("(alert|prompt|confirm|cmd|passthru|eval|exec|expression|system|fopen|fsockopen|file|file_get_contents|readfile|unlink)(\\s*)\\((.*?)\\)", boost::regex::icase);
			str=boost::regex_replace(str, expression, "$1$2&#40;$3&#41;", boost::match_perl);

			_do_never_allowed(str);


			return str;
		}
}

int main()
{

	boost::regex expression("123.*");
	std::string str = "%7f          http://%77%77%77%2E%67%6F%6F%67%6C%65%2E%63%6F%6D<span style='color:#00\n66>00;'>&asfa=asf";
	//std::cout << antiFilter::remove_xss(str) << "\n";
	str = "%25%25%25%27eval  ('some code') <    img     style=\"12<3\"  >sadfsaf&aacute;sadf</>sadfdsfsdafas<img test='jihanzhuang'&nbsp;&yuml&Aacute;/><img style='asdfsad'&nbsp&yuml&lpar&uuml;/> &nbsp=asdfsad&style=asdfsad&style=asdfsad&style=asdfsad&#x1231∏ /><script></script><a href=asdfsdafdsaalert|&#40;d  a  t  a  :></a>";
	std::cout<<antiFilter::remove_xss(str)<<"\n";
	std::string test = "http://%2E%676";
	std::cout << antiFilter::raw_url_decode(test)<<"\n";
	test = "123\n123";
	std::cout << boost::regex_replace(test, expression, "111") << "\n";
	str = " style = '12*asfsdafsadf*32' style = \"1232\"";
	std::cout<<antiFilter::_filter_attributes(str) << "\n";
	str="<    img     style='123'  >sadfsafsadf</>";
		expression.assign("<((?<slash>/*\\s*)((?<tagName>[a-z0-9]+)(?=[^a-z0-9]|$)|.+)[^\\s\042\047a-z0-9>/=]*(?<attributes>(?:[\\s\042\047/=]*[^\\s\042\047>/=]+(?:\\s*=(?:[^\\s\042\047=><`]+|\\s*\042[^\042]*\042|\\s*\047[^\047]*\047|\\s*(?:[^\\s\042\047=><`]*)))?)*)[^>]*)(?<closeTag>\>)?", boost::regex::icase);

	str = boost::regex_replace(str, expression, antiFilter::_sanitize_naughty_html, boost::match_perl);

	char line[100];
	std::cout << "Enter encoded line: ";
	std::cin.getline(line, sizeof line);
	decode_html_entities_utf8(line, 0);
	std::cout << line;
	printf("this is 1\n");
}