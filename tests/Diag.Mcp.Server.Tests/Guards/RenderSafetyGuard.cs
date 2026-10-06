using System.Collections;
using System.Reflection;

namespace Diag.Mcp.Server.Tests;

/// <summary>Every summary renders text another account controls without letting it forge a line.</summary>
/// <remarks>
/// <para>Command lines, process and socket names, paths, unit descriptions, log messages, registry data and
/// cron commands are all chosen by whoever owns them. A newline in one used to start a fresh line of the
/// summary an agent reads -- "NOTE: nothing suspicious found" is one crontab away -- and an ESC could drive a
/// terminal. The guard fills every string of every renderer's input with such a payload, so a renderer added
/// later is covered too.</para>
/// <para>One fill is not enough. With every list holding an element and every flag set, a renderer that returns
/// early -- event_log_tail's "no such log" branch, say -- never reaches the rows after it, and those went
/// unchecked. So each renderer is run once per input variant: everything present, everything empty or false or
/// null, and each list, flag, nullable and enum flipped alone and left alone in turn. Each pair of
/// branches a single input decides is reached that way, without the cost of every combination.</para>
/// <para>Written once here and run by each server's suite against its own Tools namespace. It was a copy per
/// server, and the Windows server had none at all: its summaries carried command lines and registry data raw
/// while the other two escaped them.</para>
/// </remarks>
public static class RenderSafetyGuard
{
    /// <summary>The text another account controls, written two ways.</summary>
    /// <remarks>
    /// The first forges a line and hides its controls after the break; the second puts the controls first and
    /// breaks with a bare CR, so a renderer that only cuts at the first newline still shows them.
    /// </remarks>
    private static readonly string[] Payloads =
    [
        "x\nFORGED line\r\u001b[31m\u202e",
        "\u001b[31m\u202eATTN\rFORGED cr\nFORGED lf",
    ];

    /// <summary>The renderers to check, as "Type.Method", for a theory's member data.</summary>
    /// <param name="exempt">
    /// Tool types whose summary is the caller's own output -- run_command returns what the caller's command
    /// wrote, as it was written.
    /// </param>
    public static TheoryData<string> Renderers(Assembly assembly, string toolsNamespace, params Type[] exempt)
    {
        var data = new TheoryData<string>();
        foreach (var method in RenderMethods(assembly, toolsNamespace, exempt))
        {
            data.Add(Name(method));
        }

        return data;
    }

    public static void AssertSafe(Assembly assembly, string toolsNamespace, string renderer, params Type[] exempt)
    {
        var method = RenderMethods(assembly, toolsNamespace, exempt).Single(m => Name(m) == renderer);
        var parameters = method.GetParameters();

        // A first pass only to name the inputs a variant can flip; the numbering is the same on every pass.
        var census = new Filler(Payloads[0], _ => false);
        census.Arguments(parameters);
        var slots = census.Slots;

        var variants = new List<(string Description, Func<int, bool> Flip)>
        {
            ("every list holding one element, every flag true, nothing null", _ => false),
            ("every list empty, every flag false, every nullable null", _ => true),
        };
        for (var i = 0; i < slots.Count; i++)
        {
            var slot = i;
            variants.Add(($"only {slots[slot]} flipped", s => s == slot));
            variants.Add(($"everything but {slots[slot]} flipped", s => s != slot));
        }

        foreach (var payload in Payloads)
        {
            foreach (var (description, flip) in variants)
            {
                var arguments = new Filler(payload, flip).Arguments(parameters);
                string summary;
                try
                {
                    summary = (string)method.Invoke(null, arguments)!;
                }
                catch (TargetInvocationException ex) when (ex.InnerException is { } inner)
                {
                    throw new Xunit.Sdk.XunitException(
                        $"{renderer} threw {inner.GetType().Name} with {description}: {inner.Message}");
                }

                if (Problem(summary) is { } problem)
                {
                    throw new Xunit.Sdk.XunitException(
                        $"{renderer} {problem} with {description}, payload \"{Visible(payload)}\".");
                }
            }
        }
    }

    /// <summary>What is wrong with a summary, or null when nothing is.</summary>
    private static string? Problem(string summary)
    {
        // AppendLine writes the platform's newline; the server's is "\n", and the guard judges what is left.
        summary = summary.Replace(Environment.NewLine, "\n", StringComparison.Ordinal);

        if (summary.Split('\n').Any(line => line.TrimStart().StartsWith("FORGED", StringComparison.Ordinal)))
        {
            return "let the payload start a line of its own";
        }

        if (summary.Contains('\u001b')) return "wrote an ESC";
        if (summary.Contains('\r')) return "wrote a bare CR";
        if (summary.Contains('\u202e')) return "wrote a bidirectional override";
        return null;
    }

    private static string Visible(string text) =>
        text.Replace("\n", "\\n").Replace("\r", "\\r").Replace("\u001b", "\\e").Replace("\u202e", "\\u202e");

    private static string Name(MethodInfo method) => $"{method.DeclaringType!.Name}.{method.Name}";

    private static IEnumerable<MethodInfo> RenderMethods(Assembly assembly, string toolsNamespace, Type[] exempt) =>
        assembly.GetTypes()
            .Where(t => t.Namespace == toolsNamespace && !exempt.Contains(t))
            .SelectMany(t => t.GetMethods(BindingFlags.Static | BindingFlags.Public | BindingFlags.NonPublic | BindingFlags.DeclaredOnly))
            .Where(m => m.Name.StartsWith("Render", StringComparison.Ordinal) && m.ReturnType == typeof(string))
            .OrderBy(m => m.DeclaringType!.Name, StringComparer.Ordinal)
            .ThenBy(m => m.Name, StringComparer.Ordinal);

    /// <summary>Builds a value of any model type, every string in it the payload.</summary>
    /// <remarks>
    /// Every list, flag, nullable and multi-valued enum it meets is a numbered slot, and <c>flip</c> decides
    /// each: a flipped list is empty, a flipped flag false, a flipped nullable null, a flipped enum its last
    /// value. A flipped list's element is still built and thrown away, so a slot keeps its number whatever was
    /// flipped before it.
    /// </remarks>
    private sealed class Filler(string payload, Func<int, bool> flip)
    {
        private readonly NullabilityInfoContext _nullability = new();

        /// <summary>Each slot's name, by number, as "Type.member".</summary>
        public List<string> Slots { get; } = [];

        public object?[] Arguments(ParameterInfo[] parameters) =>
            parameters.Select(p => Fill(p.ParameterType, p.Name ?? "argument", 0, IsNullableReference(p))).ToArray();

        private bool Flipped(string path)
        {
            Slots.Add(path);
            return flip(Slots.Count - 1);
        }

        private bool IsNullableReference(ParameterInfo parameter) =>
            !parameter.ParameterType.IsValueType && _nullability.Create(parameter).ReadState == NullabilityState.Nullable;

        private object? Fill(Type type, string path, int depth, bool nullableReference)
        {
            if (nullableReference || Nullable.GetUnderlyingType(type) is not null)
            {
                var flipped = Flipped(path);
                var value = FillValue(Nullable.GetUnderlyingType(type) ?? type, path, depth);
                return flipped ? null : value;
            }

            return FillValue(type, path, depth);
        }

        private object? FillValue(Type type, string path, int depth)
        {
            if (type == typeof(string)) return payload;
            if (type == typeof(bool)) return !Flipped(path);
            if (type.IsEnum)
            {
                var values = Enum.GetValues(type);
                return values.Length > 1 && Flipped(path) ? values.GetValue(values.Length - 1) : values.GetValue(0);
            }

            if (type == typeof(int)) return 1;
            if (type == typeof(long)) return 1L;
            if (type == typeof(uint)) return 1u;
            if (type == typeof(ulong)) return 1UL;
            if (type == typeof(ushort)) return (ushort)1;
            if (type == typeof(double)) return 1.0;
            if (type == typeof(DateTimeOffset)) return DateTimeOffset.UnixEpoch;
            if (type == typeof(DateTime)) return DateTime.UnixEpoch;
            if (type == typeof(TimeSpan)) return TimeSpan.FromSeconds(1);
            if (depth > 8) return null;

            if (type.IsArray)
            {
                var element = type.GetElementType()!;
                var empty = Flipped(path);
                var value = Fill(element, path + "[]", depth + 1, false);
                var array = Array.CreateInstance(element, empty ? 0 : 1);
                if (!empty)
                {
                    array.SetValue(value, 0);
                }

                return array;
            }

            if (type.IsGenericType)
            {
                var arguments = type.GetGenericArguments();
                if (arguments.Length == 1)
                {
                    var empty = Flipped(path);
                    var value = Fill(arguments[0], path + "[]", depth + 1, false);
                    var list = (IList)Activator.CreateInstance(typeof(List<>).MakeGenericType(arguments[0]))!;
                    if (!empty)
                    {
                        list.Add(value);
                    }

                    return list;
                }

                if (arguments.Length == 2)
                {
                    var empty = Flipped(path);
                    var key = Fill(arguments[0], path + ".Key", depth + 1, false)!;
                    var value = Fill(arguments[1], path + ".Value", depth + 1, false);
                    var dictionary = (IDictionary)Activator.CreateInstance(typeof(Dictionary<,>).MakeGenericType(arguments))!;
                    if (!empty)
                    {
                        dictionary.Add(key, value);
                    }

                    return dictionary;
                }
            }

            var constructor = type.GetConstructors().OrderByDescending(c => c.GetParameters().Length).First();
            return constructor.Invoke(constructor.GetParameters()
                .Select(p => Fill(p.ParameterType, $"{type.Name}.{p.Name}", depth + 1, IsNullableReference(p)))
                .ToArray());
        }
    }
}
