#pragma warning disable IL2026 // Members annotated with 'RequiresUnreferencedCodeAttribute' require dynamic access otherwise can break functionality when trimming application code

using Microsoft.AspNetCore.Http;

using System.Threading.Tasks;

namespace Microsoft.Extensions.DependencyInjection;

// This is for .NET 6, .NET 7 has Results.Empty
internal sealed class EmptyResult : IResult
    {
        internal static readonly EmptyResult Instance = new();

        public Task ExecuteAsync(HttpContext httpContext)
        {
            return Task.CompletedTask;
        }
    }
