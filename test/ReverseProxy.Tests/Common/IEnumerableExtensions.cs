using System;
using System.Collections;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace System.Linq
{
    public static class IEnumerableExtensions
    {
        public static bool IsNullOrEmpty(this IEnumerable that) {
            return that == null || !that.GetEnumerator().MoveNext();
        }
    }
}
