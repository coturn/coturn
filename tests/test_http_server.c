#include "http_server.h"

#include <unity.h>

#include <string.h>

void setUp(void) {}
void tearDown(void) {}

static void test_str_buffer_append_html_escaped_escapes_markup_chars(void) {
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append_html_escaped(sb, "<script>alert('x') & \"y\"</script>");

  TEST_ASSERT_EQUAL_STRING("&lt;script&gt;alert(&#x27;x&#x27;) &amp; &quot;y&quot;&lt;/script&gt;",
                           str_buffer_get_str(sb));
  TEST_ASSERT_NULL(strstr(str_buffer_get_str(sb), "<script>"));
  str_buffer_free(sb);
}

static void test_str_buffer_append_html_escaped_preserves_safe_text(void) {
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append_html_escaped(sb, "alice-123@example.org");

  TEST_ASSERT_EQUAL_STRING("alice-123@example.org", str_buffer_get_str(sb));
  str_buffer_free(sb);
}

static void test_str_buffer_append_html_escaped_ignores_null(void) {
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append(sb, "prefix");
  str_buffer_append_html_escaped(sb, NULL);

  TEST_ASSERT_EQUAL_STRING("prefix", str_buffer_get_str(sb));
  str_buffer_free(sb);
}

static void test_turn_html_has_unsafe_chars_detects_markup(void) {
  TEST_ASSERT_FALSE(turn_html_has_unsafe_chars(NULL));
  TEST_ASSERT_FALSE(turn_html_has_unsafe_chars(""));
  TEST_ASSERT_FALSE(turn_html_has_unsafe_chars("north.gov"));
  TEST_ASSERT_TRUE(turn_html_has_unsafe_chars("<script>"));
  TEST_ASSERT_TRUE(turn_html_has_unsafe_chars("a>b"));
  TEST_ASSERT_TRUE(turn_html_has_unsafe_chars("a\"b"));
  TEST_ASSERT_TRUE(turn_html_has_unsafe_chars("a'b"));
  TEST_ASSERT_TRUE(turn_html_has_unsafe_chars("a&b"));
}

static void test_page_header_realm_reflection_is_escaped(void) {
  /* Mirrors get_bold_admin_title embedding of session realm into HTML. */
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append(sb, " admin session realm: <b><i>");
  str_buffer_append_html_escaped(sb, "<img src=x onerror=alert(1)>");
  str_buffer_append(sb, "</i></b><br>\r\n");

  TEST_ASSERT_NULL(strstr(str_buffer_get_str(sb), "<img"));
  TEST_ASSERT_NOT_NULL(strstr(str_buffer_get_str(sb), "&lt;img"));
  str_buffer_free(sb);
}

static void test_https_print_str_value_attribute_is_escaped(void) {
  /* Mirrors https_print_str embedding of dynamic values into HTML. */
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append(sb, "<input value=\"");
  str_buffer_append_html_escaped(sb, "\" autofocus onfocus=alert(1) x=\"");
  str_buffer_append(sb, "\">");

  /* Quotes are escaped so the payload cannot break out of the attribute. */
  TEST_ASSERT_NULL(strstr(str_buffer_get_str(sb), "value=\"\""));
  TEST_ASSERT_NOT_NULL(strstr(str_buffer_get_str(sb), "value=\"&quot;"));
  str_buffer_free(sb);
}

static void test_str_buffer_append_uri_escaped_percent_encodes_query_value(void) {
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  str_buffer_append_uri_escaped(sb, "a b&c=<script>");

  TEST_ASSERT_EQUAL_STRING("a%20b%26c%3D%3Cscript%3E", str_buffer_get_str(sb));
  TEST_ASSERT_NULL(strstr(str_buffer_get_str(sb), "<script>"));
  str_buffer_free(sb);
}

static void test_str_buffer_append_grows_and_preserves_existing_content(void) {
  struct str_buffer *sb = str_buffer_new();
  TEST_ASSERT_NOT_NULL(sb);

  char chunk[1501];
  memset(chunk, 'a', sizeof(chunk) - 1);
  chunk[sizeof(chunk) - 1] = 0;

  str_buffer_append(sb, "prefix:");
  str_buffer_append(sb, chunk);

  TEST_ASSERT_EQUAL_size_t(strlen("prefix:") + strlen(chunk), str_buffer_get_str_len(sb));
  TEST_ASSERT_EQUAL_STRING_LEN("prefix:", str_buffer_get_str(sb), strlen("prefix:"));
  TEST_ASSERT_EQUAL('a', str_buffer_get_str(sb)[strlen("prefix:")]);
  TEST_ASSERT_EQUAL('a', str_buffer_get_str(sb)[str_buffer_get_str_len(sb) - 1]);
  TEST_ASSERT_EQUAL(0, str_buffer_get_str(sb)[str_buffer_get_str_len(sb)]);
  str_buffer_free(sb);
}

int main(void) {
  UNITY_BEGIN();
  RUN_TEST(test_str_buffer_append_html_escaped_escapes_markup_chars);
  RUN_TEST(test_str_buffer_append_html_escaped_preserves_safe_text);
  RUN_TEST(test_str_buffer_append_html_escaped_ignores_null);
  RUN_TEST(test_turn_html_has_unsafe_chars_detects_markup);
  RUN_TEST(test_page_header_realm_reflection_is_escaped);
  RUN_TEST(test_https_print_str_value_attribute_is_escaped);
  RUN_TEST(test_str_buffer_append_uri_escaped_percent_encodes_query_value);
  RUN_TEST(test_str_buffer_append_grows_and_preserves_existing_content);
  return UNITY_END();
}
