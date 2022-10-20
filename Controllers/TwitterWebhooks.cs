using Microsoft.AspNetCore.Mvc;
using System.Security.Cryptography;
using System.Text;
using TwitterWebhook.Models;

namespace TwitterWebhook.Controllers
{
    [ApiController]
    public class TwitterWebhooks : ControllerBase
    {
        private readonly string _twitterAPIKey;
        public TwitterWebhooks()
        {
            // will be provided by twitter when you create a developer account
            // will be a string like this - should be saved as environment variable
            _twitterAPIKey = "AAaa7OAAaa70aaaaaaaAAAAaaaaAAAA";
        }


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

    }
}
