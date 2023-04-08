use ratatui::{buffer::Buffer, layout::Rect, style::Color, widgets::Widget};

pub struct ScrollBar {
    value: usize,
    max: usize,
}

impl Default for ScrollBar {
    fn default() -> Self {
        Self { value: 0, max: 1 }
    }
}

impl ScrollBar {
    pub fn data(mut self, value: usize, max: usize) -> Self {
        self.value = value;
        self.max = max;
        self
    }
}

impl Widget for ScrollBar {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let bar_height = 2.max(area.height / 8).min(area.height);
        let start = area.y + self.value as u16 * (area.height - bar_height) / self.max as u16;
        let end = start + bar_height;

        for x in area.left()..area.right() {
            for y in area.top()..area.bottom() {
                buf.get_mut(x, y).set_bg(if (start..end).contains(&y) {
                    Color::White
                } else {
                    Color::DarkGray
                });
            }
        }
    }
}
