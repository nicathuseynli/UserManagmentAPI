using User.Managment.Service.Models;

namespace User.Managment.Service.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
