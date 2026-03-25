// Implements a Red-Black Tree of GPAs with some metadata
#ifndef ADDRESS_TREE_H__

#include <linux/rbtree.h>

struct address_tree_node {
    struct rb_node node;
    unsigned long addr;
    unsigned long tdr_pa;
    void (*unblock_callback)(unsigned long addr, unsigned long tdr_pa, unsigned char level);
    pid_t pid;
    unsigned char level;
};

static int insert_addr(struct rb_root* addr_tree, unsigned long addr, unsigned long tdr_pa, unsigned char level,
        void (*unblock_callback)(unsigned long addr, unsigned long tdr_pa, unsigned char level)) {
    struct rb_node **next = &addr_tree->rb_node, *parent = NULL;
    struct address_tree_node *new_node, *cur;

    while (*next) {
        cur = container_of(*next, struct address_tree_node, node);

        parent = *next;
        if (addr < cur->addr)
            next = &((*next)->rb_left);
        else if (addr > cur->addr)
            next = &((*next)->rb_right);
        else {
            return -EEXIST;
        }
    }

    new_node = kmalloc(sizeof(*new_node), GFP_KERNEL);
    if (!new_node)
        return -ENOMEM;

    new_node->addr = addr;
    new_node->tdr_pa = tdr_pa;
    new_node->unblock_callback = unblock_callback;
    new_node->level = level;
    new_node->pid = current->pid;

    rb_link_node(&new_node->node, parent, next);
    rb_insert_color(&new_node->node, addr_tree);

    return 0;
}

// Search for an address
static struct address_tree_node *search_addr(struct rb_root* addr_tree, unsigned long addr) {
    struct rb_node *node = addr_tree->rb_node;
    struct address_tree_node *cur;

    while (node) {
        cur = container_of(node, struct address_tree_node, node);

        if (addr < cur->addr)
            node = node->rb_left;
        else if (addr > cur->addr)
            node = node->rb_right;
        else
            return cur;
    }
    return NULL;
}

// Remove an address
static int remove_addr(struct rb_root* addr_tree, unsigned long addr) {
    struct address_tree_node *target = search_addr(addr_tree, addr);
    if (!target)
        return -ENOENT;

    rb_erase(&target->node, addr_tree);
    kfree(target);
    return 0;
}

static void destroy_address_tree(struct rb_root *addr_tree) {
    struct rb_node *node;
    struct address_tree_node *data;

    for (node = rb_first(addr_tree); node; ) {
        data = container_of(node, struct address_tree_node, node);
        node = rb_next(node);
        rb_erase(&data->node, addr_tree);
        kfree(data);
    }
}

#endif