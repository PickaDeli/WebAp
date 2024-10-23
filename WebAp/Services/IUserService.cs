using WebAp.Models;

namespace WebAp
{

    public interface IUserService
    {
        Task<IEnumerable<UserDTO>> GetUsersAsync();
        Task<UserDTO> GetUserAsync(string username);
        Task<UserDTO> NewUserAsync(User user);
        Task<bool> UpdateUserASync(User user);

        Task<bool> DeleteUserAsync(string username);

    }
}