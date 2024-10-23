using System.ComponentModel.DataAnnotations;

namespace WebAp.Models;

public class User
{
    public long Id { get; set; }

    //Eli rajoitukset tulevat muuttujan yläpuolelle!
    [MinLength(3), MaxLength(18), Required]
    public string UserName { get; set; }

    [MinLength(3), MaxLength(200), Required]
    public string Password { get; set; }

    public byte[]? Salt { get; set; }

    [MaxLength(30), EmailAddress]
    public string? Email { get; set; }
    [MaxLength(20)]

    public string? FirstName { get; set; }
    [MaxLength(20)]

    public string? LastName { get; set; }


    //DateTimet asetetaan sisäisesti, joten nullataan ne tässä
    public DateTime? JoinDate { get; set; }

    public DateTime? LastLogin { get; set; }

    public bool Deleted { get; set; }


}


//Tähän luokkaan siirrettävät tiedot
public class UserDTO
{


    //Eli rajoitukset tulevat muuttujan yläpuolelle!
    [MinLength(3), MaxLength(18)]
    public string Username { get; set; }



    [MaxLength(30), EmailAddress]
    public string? Email { get; set; }


    [MaxLength(20)]
    public string? Firstname { get; set; }


    [MaxLength(20)]
    public string? Lastname { get; set; }


    public DateTime? JoinDate { get; set; }

    public DateTime? LastLogin { get; set; }


}



