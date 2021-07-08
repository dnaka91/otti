use indoc::indoc;
use tui::{
    buffer::Buffer,
    layout::{Margin, Rect},
    widgets::{Block, Borders, Clear, Paragraph, Widget, Wrap},
};

pub struct HelpDialog;

impl Widget for HelpDialog {
    fn render(self, area: Rect, buf: &mut Buffer) {
        let area = {
            let mut draw_area = area;
            draw_area.width = 70.min(area.width);
            draw_area.height = 10.min(area.height);
            draw_area.y = area.y + (area.height - draw_area.height) / 2;
            draw_area.x = area.x + (area.width - draw_area.width) / 2;
            draw_area
        };

        Clear.render(area, buf);

        let b = Block::default().borders(Borders::ALL).title("Help");
        let text_area = b.inner(area).inner(&Margin {
            vertical: 1,
            horizontal: 1,
        });
        b.render(area, buf);

        Paragraph::new(indoc! {"
            h - Show/hide this help dialog.
            s - Show/hide the current OTP code of the selected account.
            c - Copy the current OTP code to the clipboard.
        "})
        .wrap(Wrap { trim: false })
        .render(text_area, buf);
    }
}
