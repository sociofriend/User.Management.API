using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

#pragma warning disable CA1814 // Prefer jagged arrays over multidimensional

namespace User.Management.API.Migrations
{
    /// <inheritdoc />
    public partial class UserManagementDbRolesSeeded : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "ConcurrencyStamp", "Name", "NormalizedName" },
                values: new object[,]
                {
                    { "5b6a833f-79d7-466d-82ea-e55a89eda383", "3", "HR", "Human Resources" },
                    { "5cec13b5-b756-4b7c-b9dc-78be633182d5", "2", "User", "User" },
                    { "bd8743ad-9c45-49cb-8273-7e85198fc4d8", "1", "Admin", "Admin" }
                });
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5b6a833f-79d7-466d-82ea-e55a89eda383");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "5cec13b5-b756-4b7c-b9dc-78be633182d5");

            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "bd8743ad-9c45-49cb-8273-7e85198fc4d8");
        }
    }
}
