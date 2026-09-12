#include "cJSON.h"
#include "test_framework.h"

static void test_parses_an_object(void) {
    const char *text = "{\"name\":\"cloak\",\"num\":7,\"flag\":true}";
    cJSON *root = cJSON_Parse(text);
    ASSERT_TRUE(root != NULL);
    if (root == NULL) {
        return;
    }

    cJSON *name = cJSON_GetObjectItemCaseSensitive(root, "name");
    ASSERT_TRUE(cJSON_IsString(name));
    ASSERT_EQ_INT(0, strcmp(name->valuestring, "cloak"));

    cJSON *num = cJSON_GetObjectItemCaseSensitive(root, "num");
    ASSERT_TRUE(cJSON_IsNumber(num));
    ASSERT_EQ_INT(7, (int)num->valuedouble);

    cJSON *flag = cJSON_GetObjectItemCaseSensitive(root, "flag");
    ASSERT_TRUE(cJSON_IsBool(flag));
    ASSERT_TRUE(cJSON_IsTrue(flag));

    cJSON_Delete(root);
}

static void test_rejects_malformed_input(void) {
    cJSON *root = cJSON_Parse("{\"unterminated\": ");
    ASSERT_TRUE(root == NULL);
    cJSON_Delete(root);
}

static void test_version_is_the_vendored_one(void) {
    ASSERT_EQ_INT(1, CJSON_VERSION_MAJOR);
    ASSERT_EQ_INT(7, CJSON_VERSION_MINOR);
    ASSERT_EQ_INT(19, CJSON_VERSION_PATCH);
}

TEST_MAIN_BEGIN()
    test_parses_an_object();
    test_rejects_malformed_input();
    test_version_is_the_vendored_one();
TEST_MAIN_END()
