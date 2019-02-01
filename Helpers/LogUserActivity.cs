using Microsoft.AspNetCore.Mvc.Filters;
using System.Threading.Tasks;
using System.Security.Claims;
using DatingApp.API.Data;
using Microsoft.Extensions.DependencyInjection;
using System;

namespace DatingApp.API.Helpers
{
    public class LogUserActivity : IAsyncActionFilter
    {
        public async Task OnActionExecuteAsync(ActionExecutingContext context, ActionExecutionDelegate next) 
        {
            var resultsContext = await next();

            var userId = int.Parse(resultsContext.HttpContext.User.FindFirst(ClaimTypes.NameIdentifier).Value);

            var repo = resultsContext.HttpContext.RequestServices.GetService<IDatingRepository>();

            var user = await repo.GetUser(userId);
            user.LastActive = DateTime.Now;

            await repo.SaveAll();
        }
    }
}