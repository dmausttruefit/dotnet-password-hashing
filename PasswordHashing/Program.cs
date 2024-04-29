using McMaster.Extensions.CommandLineUtils;
using PasswordHashing;

Console.WriteLine("Hello, World!");

var password = Prompt.GetPassword("Enter the plain text password:");

Console.WriteLine("The hashed password is:");
Console.WriteLine(PasswordHasher.HashPassword(password));