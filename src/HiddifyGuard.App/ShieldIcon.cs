using System.Drawing;
using System.Drawing.Drawing2D;
using System.Runtime.InteropServices;

namespace HiddifyGuard.App;

internal static class ShieldIcon
{
    public static Icon Create(Color color)
    {
        using var image = new Bitmap(32, 32);
        using (var graphics = Graphics.FromImage(image))
        using (var brush = new SolidBrush(color))
        using (var pen = new Pen(Color.White, 2.7f) { StartCap = LineCap.Round, EndCap = LineCap.Round })
        {
            graphics.SmoothingMode = SmoothingMode.AntiAlias;
            using var path = new GraphicsPath();
            path.AddLines([new PointF(16, 2), new PointF(29, 7), new PointF(27, 21),
                new PointF(22, 27), new PointF(16, 31), new PointF(10, 27), new PointF(5, 21), new PointF(3, 7)]);
            path.CloseFigure(); graphics.FillPath(brush, path);
            graphics.DrawLines(pen, [new PointF(10, 16), new PointF(14, 20), new PointF(23, 11)]);
        }
        var handle = image.GetHicon();
        try { using var icon = Icon.FromHandle(handle); return (Icon)icon.Clone(); }
        finally { DestroyIcon(handle); }
    }
    [DllImport("user32.dll")] private static extern bool DestroyIcon(IntPtr icon);
}
