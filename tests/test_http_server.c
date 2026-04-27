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
  RUN_TEST(test_str_buffer_append_uri_escaped_percent_encodes_query_value);
  RUN_TEST(test_str_buffer_append_grows_and_preserves_existing_content);
  return UNITY_END();
}
