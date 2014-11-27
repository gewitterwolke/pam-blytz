#include <string>

std::string replace(std::string str, char what, char replacement) {
	std::string res = str;
	for (unsigned int i = 0; i < str.length(); i++) {
		if (str.at(i) == what)
			res.at(i) = replacement;
	}
	return res;
}
