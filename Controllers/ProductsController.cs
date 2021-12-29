using IdentityNetCore.Models;
using Microsoft.AspNetCore.Mvc;
using System.Collections.Generic;

namespace IdentityNetCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class ProductsController : ControllerBase
    {

        [Route(template: "List")]
        public List<Product> GetList()
        {
            var chair = new Product { Name = "Chair", Price = 100 };
            var desk = new Product { Name = "Desk", Price = 50 };

            return new List<Product> { chair, desk };
        }
    }
}
