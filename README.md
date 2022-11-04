# Dot-Net---Securing-Twitter-Webhook-Account Activity API
Dot Net Core 6 - how to secure your webhook API while using Twitter Account Activity API according to Twitter documentation.

## Introduction
This project focuses on how to secure your Twitter webhook API. We will skip the steps of creating a Twitter developer account and a Twitter application.
But you can follow this [Getting started with webhooks](https://developer.twitter.com/en/docs/twitter-api/premium/account-activity-api/guides/getting-started-with-webhooks) 
as a start.

## Prerequisites
1. Developer account on Twitter
2. Application in Twitter Developer Platform
3. Twitter API Key (something like "AAaa7OAAaa70aaaaaaaAAAAaaaaAAAA")

## Securing your webhook consumer API app
As per [Securing webhooks in Twitter documentation](https://developer.twitter.com/en/docs/twitter-api/premium/account-activity-api/guides/securing-webhooks), Twitter's webhook-based APIs provide two methods for confirming the security of your webhook server.
1. The challenge-response checks enable Twitter to confirm the ownership of the web app receiving webhook events. **(Mandatory)**
2. The signature header in each POST request enables you to confirm that Twitter is the source of the incoming webhooks. **(Optional)**

#### Challenge-Response Checks (CRC)
In the consumer API, an endpoint should be ready to be called by Twitter API to verify the owner of the consumer app.
***Steps:***
1. A crc_token variable will be sent by Twitter in the query string.
2. Hash this crc_token using the API key from the prerequisites.
3. Return the output in the response  with the appropriate format

The following code in c# shows the logic: (Note: for simplicity, all the logic is added in the controller)
```
        [HttpGet("/webhooks/twitter")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public IActionResult GetChallengeResponseCheckResult([FromQuery] TwitterCRCRequestModel model)
        {
            // Step 1: hash the crc_token using the twitter api key
            byte[] hashedTokenInBytes;
            byte[] keyInBytes = Encoding.ASCII.GetBytes(_twitterAPIKey);
            using (var hmac = new HMACSHA256(keyInBytes))
            {
                hashedTokenInBytes = hmac.ComputeHash(Encoding.ASCII.GetBytes(model.crc_token));
            }

            // Step 2: prepare the response format
            var response_token = Convert.ToBase64String(hashedTokenInBytes);
            var result = new { 
                response_token = string.Concat("sha256=", response_token)
            };

            // Step 3: return the result
            return StatusCode(200, result);
        }
```


#### Signature Header Validation
This is an optional validation in the consumer app. In which, the consumer makes sure that the source of this request is twitter.

In the endpoint that should receive the request from twitter, we should implement the following steps:
1. Get the signature from the headers and convert it to a bytes array.
2. Get the request body value.
3. Get the hashed body as a bytes array using the Twitter API key
4. Validate that the sender is twitter by comparing the bytes arrays outputs from steps 1 and 3


```
      [HttpPost("/webhooks/twitter")]
        [ApiExplorerSettings(IgnoreApi = true)]
        public async Task<IActionResult> AddTwitterActivity()
        {
            // Step 1: get the signature as bytes array from the headers
            var twitter_signature = Request.Headers["x-twitter-webhooks-signature"];
            var cleanTwitterSignature = twitter_signature.ToString().Replace("sha256=", "");
            var cleanTwitterSignature_bytes = Convert.FromBase64String(cleanTwitterSignature);

            // Step 2: get the body value
            var bodyStream = new StreamReader(HttpContext.Request.Body);
            var body_ = bodyStream.ReadToEndAsync();
            var body = await body_;

            if (body_ == null || string.IsNullOrEmpty(body))
            {
                return BadRequest();
            }

            // Step 3: Get the hashed body as bytes array using the twitter api key 
            byte[] hashedBodyInBytes;
            byte[] keyBytes = Encoding.ASCII.GetBytes(_twitterAPIKey);
            using (var hmac = new HMACSHA256(keyBytes))
            {
                hashedBodyInBytes = hmac.ComputeHash(Encoding.ASCII.GetBytes(body));
            }

            // Step 4: Validate that the sender is twitter by comparing the bytes arrays outputs from steps 1 and 3
            // The following implementation logic is to avoid the timing attack
            // references:
            // https://stackoverflow.com/questions/4571691/hash-digest-array-comparison-in-c-sharp
            // https://codahale.com/a-lesson-in-timing-attacks/

            bool isRequestValid = false;
            if (cleanTwitterSignature_bytes.Length == hashedBodyInBytes.Length)
            {
                bool res = true;
                for (int i = 0; i < cleanTwitterSignature_bytes.Length; i++)
                {
                    res = res & (cleanTwitterSignature_bytes[i] == hashedBodyInBytes[i]);
                }
                isRequestValid = res;
            }


            // Step 5: Process the request if the request is valid
            if (isRequestValid)
            {
                // process the request
                return StatusCode(200);
            }
            else
            {
                return StatusCode(401);
            }
        }
```
