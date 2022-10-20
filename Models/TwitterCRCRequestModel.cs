using System.ComponentModel.DataAnnotations;

namespace TwitterWebhook.Models
{
    public class TwitterCRCRequestModel
    {
        [Required]
        public string crc_token { get; set; } //challenge response check token
    }
}
