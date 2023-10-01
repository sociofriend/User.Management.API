using User.Management.Services.Models;

namespace User.Management.Services.Services
{
    public interface IEmailService
    {
        public void SendEmail(Message message);
    }
}