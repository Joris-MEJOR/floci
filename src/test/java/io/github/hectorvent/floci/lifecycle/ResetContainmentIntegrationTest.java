package io.github.hectorvent.floci.lifecycle;

import io.quarkus.test.junit.QuarkusTest;
import io.restassured.RestAssured;
import io.restassured.config.EncoderConfig;
import io.restassured.http.ContentType;
import io.restassured.parsing.Parser;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static io.restassured.RestAssured.given;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.hasItem;

/**
 * One failing {@code Resettable.clear()} must not abort the reset transition: every other
 * service still clears, storage still clears, and the caller learns about the failure through a
 * 500 {@code PARTIAL} instead of a false {@code OK}.
 */
@QuarkusTest
class ResetContainmentIntegrationTest {

    private static final String JSON_1_0 = "application/x-amz-json-1.0";

    @BeforeAll
    static void registerParsers() {
        RestAssured.registerParser(JSON_1_0, Parser.JSON);
    }

    @AfterEach
    void disarmAndClean() {
        ThrowingResettable.ARMED.set(false);
        given().when().post("/_floci/state/reset").then().statusCode(200);
    }

    @Test
    void armedFailureReportsPartialButStillClearsEverythingElse() {
        // Seed storage-backed state (a DynamoDB table) that the reset must still remove.
        given().config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig()
                        .encodeContentTypeAs(JSON_1_0, ContentType.TEXT)))
                .header("X-Amz-Target", "DynamoDB_20120810.CreateTable")
                .contentType(JSON_1_0)
                .body("""
                        {"TableName":"containment-table",
                         "KeySchema":[{"AttributeName":"pk","KeyType":"HASH"}],
                         "AttributeDefinitions":[{"AttributeName":"pk","AttributeType":"S"}],
                         "BillingMode":"PAY_PER_REQUEST"}
                        """)
                .when().post("/").then().statusCode(200);

        ThrowingResettable.ARMED.set(true);
        given().when().post("/_floci/state/reset")
                .then().statusCode(500)
                .body("status", equalTo("PARTIAL"))
                .body("failed", hasItem("ThrowingResettable"));
        ThrowingResettable.ARMED.set(false);

        // Storage was still cleared despite the armed failure.
        given().config(RestAssured.config().encoderConfig(EncoderConfig.encoderConfig()
                        .encodeContentTypeAs(JSON_1_0, ContentType.TEXT)))
                .header("X-Amz-Target", "DynamoDB_20120810.DescribeTable")
                .contentType(JSON_1_0)
                .body("{\"TableName\":\"containment-table\"}")
                .when().post("/").then().statusCode(400);
    }
}
