use otti_core::Account;
use ratatui::{
    buffer::Buffer,
    layout::Rect,
    style::Color,
    widgets::{Block, Paragraph, StatefulWidget, Widget},
};

use super::ScrollBar;

const LIST_ITEM_HEIGHT: usize = 4;

pub struct List<'a> {
    block: Option<Block<'a>>,
    scrollbar: Option<(ScrollBar, u16)>,
    items: &'a [Account],
}

impl<'a> List<'a> {
    pub fn new(items: &'a [Account]) -> Self {
        Self {
            block: None,
            scrollbar: None,
            items,
        }
    }

    pub fn block(mut self, block: Block<'a>) -> Self {
        self.block = Some(block);
        self
    }

    pub fn scrollbar(mut self, scrollbar: ScrollBar, width: u16) -> Self {
        self.scrollbar = Some((scrollbar, width));
        self
    }
}

impl<'a> StatefulWidget for List<'a> {
    type State = State;

    fn render(mut self, area: Rect, buf: &mut Buffer, state: &mut Self::State) {
        let list_area = match self.block.take() {
            Some(b) => {
                let inner_area = b.inner(area);
                b.render(area, buf);
                inner_area
            }
            None => area,
        };

        let (scrollbar, scrollbar_width) = match self.scrollbar {
            Some((scrollbar, width)) => (Some(scrollbar), width),
            None => (None, 0),
        };

        state.update_scroll_pos(list_area);

        for (i, item) in self.items.iter().skip(state.scroll_pos).enumerate() {
            let mut area = list_area;
            area.y += (i * LIST_ITEM_HEIGHT) as u16;
            area.height = 1;
            area.width -= scrollbar_width;

            // Draw current selection indicator
            if state.position() == i {
                for y in area.y..list_area.bottom().min(area.y + 3) {
                    buf.get_mut(area.x, y).set_bg(Color::Blue);
                }
            }

            area.x += 2;
            area.width -= 2;

            // Draw the item label
            area.y += 1;
            if area.y >= list_area.bottom() {
                break;
            }
            Paragraph::new(item.label.as_str()).render(area, buf);

            // Draw the item issuer
            area.y += 1;
            if area.y >= list_area.bottom() {
                break;
            }
            if let Some(issuer) = &item.issuer {
                Paragraph::new(issuer.as_str()).render(area, buf);
            }

            // Draw the separator
            area.y += 1;
            if area.y >= list_area.bottom() {
                break;
            }

            area.x -= 2;
            area.width += 2;

            (area.x..area.width).for_each(|x| {
                buf.get_mut(x, area.y).set_char('─');
            });
        }

        // Draw scroll bar, if set
        if let Some(scrollbar) = scrollbar {
            let mut area = list_area;
            area.x += area.width - scrollbar_width;
            area.width = scrollbar_width;

            scrollbar
                .data(state.selection, self.items.len() - 1)
                .render(area, buf);
        }
    }
}

#[derive(Default)]
pub struct State {
    selection: usize,
    scroll_pos: usize,
}

impl State {
    pub fn up(&mut self, _items: &[Account]) {
        if self.selection > 0 {
            self.selection -= 1;
        }
    }

    pub fn down(&mut self, items: &[Account]) {
        if self.selection < items.len() - 1 {
            self.selection += 1;
        }
    }

    pub fn selection(&self) -> usize {
        self.selection
    }

    fn update_scroll_pos(&mut self, area: Rect) {
        while (self.selection + 1).saturating_sub(self.scroll_pos) * LIST_ITEM_HEIGHT
            > usize::from(area.height)
        {
            self.scroll_pos += 1;
        }

        while self.selection < self.scroll_pos {
            self.scroll_pos -= 1;
        }
    }

    fn position(&self) -> usize {
        self.selection - self.scroll_pos
    }
}
