use tui::{
    buffer::Buffer,
    layout::{Alignment, Rect},
    widgets::{Block, Borders, Clear, Paragraph, Widget},
};

pub struct CodeDialog<'a> {
    code: &'a str,
}

impl<'a> CodeDialog<'a> {
    pub fn new(code: &'a str) -> Self {
        Self { code }
    }
}

impl<'a> Widget for CodeDialog<'a> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let area = {
            let mut draw_area = area;
            draw_area.width = 20.min(area.width);
            draw_area.height = 5.min(area.height);
            draw_area.y = area.y + (area.height - draw_area.height) / 2;
            draw_area.x = area.x + (area.width - draw_area.width) / 2;
            draw_area
        };

        Clear.render(area, buf);

        let b = Block::default().borders(Borders::ALL);
        let mut text_area = b.inner(area);
        b.render(area, buf);

        text_area.y += 1;
        text_area.height = 1;

        Paragraph::new(self.code)
            .alignment(Alignment::Center)
            .render(text_area, buf);
    }
}
